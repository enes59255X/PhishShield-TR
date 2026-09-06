/**
 * PhishShield TR - Mobile App Models
 */

class AnalysisResult {
  final String url;
  final String domain;
  final String decision;
  final int riskScore;
  final int confidence;
  final List<String> reasons;
  final DateTime timestamp;
  final bool cached;

  AnalysisResult({
    required this.url,
    required this.domain,
    required this.decision,
    required this.riskScore,
    required this.confidence,
    required this.reasons,
    required this.timestamp,
    this.cached = false,
  });

  factory AnalysisResult.fromJson(Map<String, dynamic> json) {
    return AnalysisResult(
      url: json['url'] ?? '',
      domain: json['domain'] ?? _extractDomain(json['url'] ?? ''),
      decision: json['decision'] ?? 'UNKNOWN',
      riskScore: json['risk_score'] ?? 0,
      confidence: json['confidence'] ?? 0,
      reasons: List<String>.from(json['reasons'] ?? []),
      timestamp: DateTime.now(),
      cached: json['cached'] ?? false,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'url': url,
      'domain': domain,
      'decision': decision,
      'risk_score': riskScore,
      'confidence': confidence,
      'reasons': reasons,
      'timestamp': timestamp.toIso8601String(),
      'cached': cached,
    };
  }

  static String _extractDomain(String url) {
    try {
      final uri = Uri.parse(url);
      return uri.host;
    } catch {
      return url;
    }
  }

  bool get isSafe => decision == 'SAFE';
  bool get isDanger => decision == 'DANGER' || decision == 'BLOCK';
  bool get needsReview => decision == 'REVIEW';
}

class ScanHistory {
  final List<AnalysisResult> scans;
  final int todayCount;
  final int totalCount;

  ScanHistory({
    required this.scans,
    required this.todayCount,
    required this.totalCount,
  });

  factory ScanHistory.empty() {
    return ScanHistory(scans: [], todayCount: 0, totalCount: 0);
  }
}

class AppSettings {
  final bool protectionEnabled;
  final bool notificationsEnabled;
  final bool autoScan;
  final String apiUrl;
  final int cacheTTL;

  AppSettings({
    this.protectionEnabled = true,
    this.notificationsEnabled = true,
    this.autoScan = true,
    this.apiUrl = 'http://127.0.0.1:8004',
    this.cacheTTL = 300,
  });

  AppSettings copyWith({
    bool? protectionEnabled,
    bool? notificationsEnabled,
    bool? autoScan,
    String? apiUrl,
    int? cacheTTL,
  }) {
    return AppSettings(
      protectionEnabled: protectionEnabled ?? this.protectionEnabled,
      notificationsEnabled: notificationsEnabled ?? this.notificationsEnabled,
      autoScan: autoScan ?? this.autoScan,
      apiUrl: apiUrl ?? this.apiUrl,
      cacheTTL: cacheTTL ?? this.cacheTTL,
    );
  }
}

class AlertItem {
  final String id;
  final String title;
  final String message;
  final String severity;
  final DateTime timestamp;
  final bool resolved;

  AlertItem({
    required this.id,
    required this.title,
    required this.message,
    required this.severity,
    required this.timestamp,
    this.resolved = false,
  });

  factory AlertItem.fromJson(Map<String, dynamic> json) {
    return AlertItem(
      id: json['id'] ?? '',
      title: json['title'] ?? '',
      message: json['message'] ?? '',
      severity: json['severity'] ?? 'INFO',
      timestamp: DateTime.tryParse(json['timestamp'] ?? '') ?? DateTime.now(),
      resolved: json['resolved'] ?? false,
    );
  }
}
