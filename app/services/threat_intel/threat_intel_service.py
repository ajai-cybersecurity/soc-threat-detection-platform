"""
Enhanced Threat Intelligence Service - Phase 1.

Advanced threat intelligence with:
- Provider abstraction (VirusTotal, AbuseIPDB, OTX)
- Intelligent caching with TTL
- Background job enrichment
- Rate limiting
- Automatic alert enrichment
"""

import json
import logging
from datetime import datetime, timedelta
from flask import current_app
from app.models.models import db, ThreatIntelCache, Alert

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """
    Enhanced Threat Intelligence Service.
    
    Features:
    - Multi-provider enrichment (VT, AbuseIPDB, OTX)
    - Intelligent caching with automatic expiration
    - Background job support for batch enrichment
    - Rate limiting to respect API quotas
    - Unified API for all lookups
    """
    
    def __init__(self):
        """Initialize threat intelligence service without requiring app context."""
        self.cache_ttl = None
        self.batch_size = None
        self._initialized = False
    
    def _ensure_initialized(self):
        if self._initialized:
            return
        self._initialized = True
        try:
            self.cache_ttl = current_app.config.get('TI_CACHE_TTL', 86400)  # 24 hours
            self.batch_size = current_app.config.get('TI_BATCH_SIZE', 50)
        except RuntimeError:
            # If no app context is available, fall back to defaults
            self.cache_ttl = 86400
            self.batch_size = 50
    
    def enrich_indicator(self, indicator: str, indicator_type: str = 'ip',
                        use_cache: bool = True, store_in_db: bool = True) -> dict:
        """
        Enrich a single indicator with threat intelligence.
        
        Args:
            indicator: Indicator to enrich (IP, domain, hash, URL)
            indicator_type: Type of indicator (ip/domain/hash/url)
            use_cache: Use cached results if available
            store_in_db: Store results in database
            
        Returns:
            Enriched data with scores, tags, and provider information
        """
        self._ensure_initialized()
        # Check cache first
        if use_cache:
            cached = self._get_cached(indicator, indicator_type)
            if cached:
                logger.info(f"Cache HIT for {indicator}")
                return cached
        
        try:
            # Import here to avoid circular imports
            from app.intelligence.threat_intel import intel_client
            
            enrichment = {
                'indicator': indicator,
                'indicator_type': indicator_type,
                'malicious_score': 0.0,
                'suspicious_score': 0.0,
                'harmless_score': 0.0,
                'reputation_score': 0.0,
                'providers': {},
                'is_malicious': False,
                'tags': [],
                'country': '',
                'asn': '',
                'isp': '',
            }
            
            # Call all threat intel providers
            if indicator_type == 'ip':
                # AbuseIPDB
                abuse_result = intel_client.check_abuseipdb(indicator)
                if 'error' not in abuse_result:
                    enrichment['providers']['abuseipdb'] = abuse_result
                    enrichment['reputation_score'] = max(
                        enrichment['reputation_score'],
                        abuse_result.get('reputation_score', 0)
                    )
                    enrichment['country'] = abuse_result.get('country', '')
                    enrichment['isp'] = abuse_result.get('isp', '')
            
            # VirusTotal (all types)
            vt_result = intel_client.check_virustotal(indicator, indicator_type)
            if 'error' not in vt_result:
                enrichment['providers']['virustotal'] = vt_result
                enrichment['malicious_score'] = max(
                    enrichment['malicious_score'],
                    vt_result.get('reputation_score', 0)
                )
                enrichment['tags'].extend(vt_result.get('tags', '').split(', '))
                enrichment['country'] = enrichment['country'] or vt_result.get('country', '')
                enrichment['asn'] = enrichment['asn'] or vt_result.get('asn', '')
            
            # OTX (all types)
            otx_result = intel_client.check_otx(indicator, indicator_type)
            if 'error' not in otx_result:
                enrichment['providers']['otx'] = otx_result
                enrichment['suspicious_score'] = max(
                    enrichment['suspicious_score'],
                    otx_result.get('reputation_score', 0)
                )
                enrichment['tags'].extend(otx_result.get('tags', '').split(', '))
                enrichment['country'] = enrichment['country'] or otx_result.get('country', '')
            
            # Calculate unified reputation
            enrichment['reputation_score'] = max(
                enrichment['malicious_score'],
                enrichment['suspicious_score'],
                enrichment['reputation_score']
            )
            
            enrichment['is_malicious'] = enrichment['reputation_score'] >= 50
            enrichment['tags'] = list(set(filter(None, enrichment['tags'])))[:20]
            
            # Store in cache/database
            if store_in_db:
                self._store_enrichment(indicator, indicator_type, enrichment)
            
            logger.info(f"Enriched {indicator} - malicious: {enrichment['is_malicious']}")
            return enrichment
            
        except Exception as e:
            logger.error(f"Enrichment error for {indicator}: {e}")
            return {
                'indicator': indicator,
                'error': str(e),
                'malicious_score': 0.0,
                'reputation_score': 0.0,
                'is_malicious': False,
            }
    
    def _get_cached(self, indicator: str, indicator_type: str) -> dict or None:
        """Retrieve cached enrichment if not expired."""
        try:
            cache_entry = ThreatIntelCache.query.filter_by(
                indicator=indicator,
                indicator_type=indicator_type
            ).first()
            
            if not cache_entry:
                return None
            
            if cache_entry.is_expired():
                db.session.delete(cache_entry)
                db.session.commit()
                return None
            
            return {
                'indicator': indicator,
                'indicator_type': indicator_type,
                'malicious_score': cache_entry.malicious_score,
                'suspicious_score': cache_entry.suspicious_score,
                'harmless_score': cache_entry.harmless_score,
                'reputation_score': cache_entry.reputation_score,
                'is_malicious': cache_entry.is_malicious,
                'tags': cache_entry.tags.split(', ') if cache_entry.tags else [],
                'country': cache_entry.country,
                'asn': cache_entry.asn,
                'isp': cache_entry.isp,
                'cached': True,
            }
        except Exception as e:
            logger.error(f"Cache retrieval error: {e}")
            return None
    
    def _store_enrichment(self, indicator: str, indicator_type: str, enrichment: dict):
        """Store enrichment in database cache."""
        try:
            # Check if already exists
            cache_entry = ThreatIntelCache.query.filter_by(indicator=indicator).first()
            
            if cache_entry:
                # Update existing
                cache_entry.malicious_score = enrichment.get('malicious_score', 0)
                cache_entry.suspicious_score = enrichment.get('suspicious_score', 0)
                cache_entry.harmless_score = enrichment.get('harmless_score', 0)
                cache_entry.reputation_score = enrichment.get('reputation_score', 0)
                cache_entry.is_malicious = enrichment.get('is_malicious', False)
                cache_entry.tags = ', '.join(enrichment.get('tags', []))
                cache_entry.country = enrichment.get('country', '')
                cache_entry.asn = enrichment.get('asn', '')
                cache_entry.isp = enrichment.get('isp', '')
                cache_entry.cached_at = datetime.utcnow()
                cache_entry.expires_at = datetime.utcnow() + timedelta(seconds=self.cache_ttl)
                
                # Store provider data
                providers = enrichment.get('providers', {})
                if 'virustotal' in providers:
                    cache_entry.virustotal_data = json.dumps(providers['virustotal'])
                if 'abuseipdb' in providers:
                    cache_entry.abuseipdb_data = json.dumps(providers['abuseipdb'])
                if 'otx' in providers:
                    cache_entry.otx_data = json.dumps(providers['otx'])
            else:
                # Create new
                cache_entry = ThreatIntelCache(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    malicious_score=enrichment.get('malicious_score', 0),
                    suspicious_score=enrichment.get('suspicious_score', 0),
                    harmless_score=enrichment.get('harmless_score', 0),
                    reputation_score=enrichment.get('reputation_score', 0),
                    is_malicious=enrichment.get('is_malicious', False),
                    tags=', '.join(enrichment.get('tags', [])),
                    country=enrichment.get('country', ''),
                    asn=enrichment.get('asn', ''),
                    isp=enrichment.get('isp', ''),
                    expires_at=datetime.utcnow() + timedelta(seconds=self.cache_ttl),
                    virustotal_data=json.dumps(enrichment.get('providers', {}).get('virustotal', {})),
                    abuseipdb_data=json.dumps(enrichment.get('providers', {}).get('abuseipdb', {})),
                    otx_data=json.dumps(enrichment.get('providers', {}).get('otx', {})),
                )
                db.session.add(cache_entry)
            
            db.session.commit()
            logger.info(f"Stored enrichment for {indicator}")
            
        except Exception as e:
            logger.error(f"Storage error: {e}")
            db.session.rollback()
    
    def enrich_alert_automatically(self, alert: Alert) -> bool:
        """
        Automatically enrich an alert with threat intelligence.
        
        Args:
            alert: Alert object to enrich
            
        Returns:
            True if enrichment successful
        """
        try:
            enrichment = self.enrich_indicator(
                alert.source_ip,
                'ip',
                use_cache=True,
                store_in_db=True
            )
            
            # Update alert with enrichment data
            alert.raw_evidence = json.dumps({
                'original_evidence': json.loads(alert.raw_evidence or '{}'),
                'threat_intel': enrichment
            })
            
            db.session.commit()
            logger.info(f"Alert {alert.id} enriched with threat intel")
            return True
            
        except Exception as e:
            logger.error(f"Alert enrichment error: {e}")
            return False
    
    def batch_enrich_alerts(self, alert_ids: list = None, limit: int = None) -> dict:
        """
        Batch enrich multiple alerts.
        
        Args:
            alert_ids: Specific alerts to enrich (None = all unenriched)
            limit: Maximum alerts to process
            
        Returns:
            Results with success count, failed count, etc.
        """
        try:
            if alert_ids:
                alerts = Alert.query.filter(Alert.id.in_(alert_ids)).limit(limit).all()
            else:
                # Get unenriched alerts
                alerts = Alert.query.filter(
                    (Alert.raw_evidence.isnot(None)) |
                    (~Alert.raw_evidence.contains('threat_intel'))
                ).limit(limit or self.batch_size).all()
            
            results = {
                'total': len(alerts),
                'successful': 0,
                'failed': 0,
                'errors': []
            }
            
            for alert in alerts:
                try:
                    if self.enrich_alert_automatically(alert):
                        results['successful'] += 1
                    else:
                        results['failed'] += 1
                except Exception as e:
                    results['failed'] += 1
                    results['errors'].append(f"Alert {alert.id}: {str(e)}")
            
            logger.info(f"Batch enrichment: {results['successful']} successful, {results['failed']} failed")
            return results
            
        except Exception as e:
            logger.error(f"Batch enrichment error: {e}")
            return {'error': str(e)}
    
    def clear_expired_cache(self) -> int:
        """
        Delete expired cache entries.
        
        Returns:
            Number of entries deleted
        """
        try:
            expired_entries = ThreatIntelCache.query.filter(
                ThreatIntelCache.expires_at < datetime.utcnow()
            ).all()
            
            count = len(expired_entries)
            for entry in expired_entries:
                db.session.delete(entry)
            
            db.session.commit()
            logger.info(f"Cleared {count} expired cache entries")
            return count
            
        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")
            db.session.rollback()
            return 0


# Global threat intel service instance
threat_intel_service = ThreatIntelService()
