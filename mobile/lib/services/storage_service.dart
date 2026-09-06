/**
 * PhishShield TR - Storage Service
 * Local data persistence
 */

import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/models.dart';

class StorageService {
  static const String _historyKey = 'scan_history';
  static const String _settingsKey = 'app_settings';
  static const String _alertsKey = 'alerts';
  static const int _maxHistoryItems = 100;

  SharedPreferences? _prefs;

  Future<void> init() async {
    _prefs = await SharedPreferences.getInstance();
  }

  /**
   * Scan history islemleri
   */
  Future<List<AnalysisResult>> getHistory() async {
    await _ensureInit();
    final jsonStr = _prefs!.getString(_historyKey);
    if (jsonStr == null) return [];

    try {
      final List<dynamic> jsonList = jsonDecode(jsonStr);
      return jsonList.map((j) => AnalysisResult.fromJson(j)).toList();
    } catch {
      return [];
    }
  }

  Future<void> addToHistory(AnalysisResult result) async {
    await _ensureInit();
    final history = await getHistory();
    history.insert(0, result);

    // Limit history size
    if (history.length > _maxHistoryItems) {
      history.removeRange(_maxHistoryItems, history.length);
    }

    await _prefs!.setString(
      _historyKey,
      jsonEncode(history.map((r) => r.toJson()).toList()),
    );
  }

  Future<void> clearHistory() async {
    await _ensureInit();
    await _prefs!.remove(_historyKey);
  }

  Future<void> removeFromHistory(String url) async {
    await _ensureInit();
    final history = await getHistory();
    history.removeWhere((r) => r.url == url);
    await _prefs!.setString(
      _historyKey,
      jsonEncode(history.map((r) => r.toJson()).toList()),
    );
  }

  /**
   * Settings islemleri
   */
  Future<AppSettings> getSettings() async {
    await _ensureInit();
    final jsonStr = _prefs!.getString(_settingsKey);
    if (jsonStr == null) return AppSettings();

    try {
      final json = jsonDecode(jsonStr);
      return AppSettings(
        protectionEnabled: json['protectionEnabled'] ?? true,
        notificationsEnabled: json['notificationsEnabled'] ?? true,
        autoScan: json['autoScan'] ?? true,
        apiUrl: json['apiUrl'] ?? 'http://127.0.0.1:8004',
        cacheTTL: json['cacheTTL'] ?? 300,
      );
    } catch {
      return AppSettings();
    }
  }

  Future<void> saveSettings(AppSettings settings) async {
    await _ensureInit();
    await _prefs!.setString(_settingsKey, jsonEncode({
      'protectionEnabled': settings.protectionEnabled,
      'notificationsEnabled': settings.notificationsEnabled,
      'autoScan': settings.autoScan,
      'apiUrl': settings.apiUrl,
      'cacheTTL': settings.cacheTTL,
    }));
  }

  /**
   * Alerts islemleri
   */
  Future<List<AlertItem>> getAlerts() async {
    await _ensureInit();
    final jsonStr = _prefs!.getString(_alertsKey);
    if (jsonStr == null) return [];

    try {
      final List<dynamic> jsonList = jsonDecode(jsonStr);
      return jsonList.map((j) => AlertItem.fromJson(j)).toList();
    } catch {
      return [];
    }
  }

  Future<void> addAlert(AlertItem alert) async {
    await _ensureInit();
    final alerts = await getAlerts();
    alerts.insert(0, alert);

    if (alerts.length > _maxHistoryItems) {
      alerts.removeRange(_maxHistoryItems, alerts.length);
    }

    await _prefs!.setString(
      _alertsKey,
      jsonEncode(alerts.map((a) => {
        'id': a.id,
        'title': a.title,
        'message': a.message,
        'severity': a.severity,
        'timestamp': a.timestamp.toIso8601String(),
        'resolved': a.resolved,
      }).toList()),
    );
  }

  Future<void> clearAlerts() async {
    await _ensureInit();
    await _prefs!.remove(_alertsKey);
  }

  Future<void> resolveAlert(String id) async {
    await _ensureInit();
    final alerts = await getAlerts();
    final index = alerts.indexWhere((a) => a.id == id);
    if (index != -1) {
      final alert = alerts[index];
      alerts[index] = AlertItem(
        id: alert.id,
        title: alert.title,
        message: alert.message,
        severity: alert.severity,
        timestamp: alert.timestamp,
        resolved: true,
      );
      await _prefs!.setString(
        _alertsKey,
        jsonEncode(alerts.map((a) => {
          'id': a.id,
          'title': a.title,
          'message': a.message,
          'severity': a.severity,
          'timestamp': a.timestamp.toIso8601String(),
          'resolved': a.resolved,
        }).toList()),
      );
    }
  }

  /**
   * Statistics
   */
  Future<Map<String, int>> getStats() async {
    final history = await getHistory();
    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);

    int todayCount = 0;
    int dangerCount = 0;

    for (final scan in history) {
      if (scan.timestamp.isAfter(today)) {
        todayCount++;
      }
      if (scan.isDanger) {
        dangerCount++;
      }
    }

    return {
      'total': history.length,
      'today': todayCount,
      'danger': dangerCount,
    };
  }

  Future<void> _ensureInit() async {
    _prefs ??= await SharedPreferences.getInstance();
  }
}
