/**
 * PhishShield TR - Profile Screen
 * Settings and user preferences
 */

import 'package:flutter/material.dart';
import '../models/models.dart';
import '../services/services.dart';

class ProfileScreen extends StatefulWidget {
  final StorageService storageService;
  final ApiService apiService;

  const ProfileScreen({
    super.key,
    required this.storageService,
    required this.apiService,
  });

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  AppSettings _settings = AppSettings();
  Map<String, int> _stats = {};
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);
    try {
      final settings = await widget.storageService.getSettings();
      final stats = await widget.storageService.getStats();
      setState(() {
        _settings = settings;
        _stats = stats;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _updateSettings(AppSettings newSettings) async {
    await widget.storageService.saveSettings(newSettings);
    setState(() => _settings = newSettings);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Ayarlar'),
        backgroundColor: const Color(0xFF1a1a2e),
        foregroundColor: Colors.white,
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF1a1a2e), Color(0xFF16213e)],
          ),
        ),
        child: _isLoading
            ? const Center(child: CircularProgressIndicator())
            : SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Stats Card
                    _buildStatsCard(),
                    const SizedBox(height: 24),

                    // Protection Settings
                    _buildSectionTitle('Koruma Ayarlari'),
                    const SizedBox(height: 12),
                    _buildSwitchTile(
                      'Koruma Aktif',
                      'Phishing korumasi',
                      Icons.shield,
                      _settings.protectionEnabled,
                      (value) => _updateSettings(
                        _settings.copyWith(protectionEnabled: value),
                      ),
                    ),
                    _buildSwitchTile(
                      'Bildirimler',
                      'Tehlikeli site bildirimi',
                      Icons.notifications,
                      _settings.notificationsEnabled,
                      (value) => _updateSettings(
                        _settings.copyWith(notificationsEnabled: value),
                      ),
                    ),
                    _buildSwitchTile(
                      'Otomatik Tarama',
                      'Linkler otomatik tara',
                      Icons.auto_awesome,
                      _settings.autoScan,
                      (value) => _updateSettings(
                        _settings.copyWith(autoScan: value),
                      ),
                    ),
                    const SizedBox(height: 24),

                    // API Settings
                    _buildSectionTitle('API Ayarlari'),
                    const SizedBox(height: 12),
                    _buildApiUrlTile(),
                    const SizedBox(height: 24),

                    // Cache Settings
                    _buildSectionTitle('Onbellek'),
                    const SizedBox(height: 12),
                    _buildCacheTTLTile(),
                    const SizedBox(height: 24),

                    // Actions
                    _buildSectionTitle('Eylemler'),
                    const SizedBox(height: 12),
                    _buildActionTile(
                      'Gecmisi Temizle',
                      'Tum tarama gecmisini sil',
                      Icons.history,
                      () async {
                        await widget.storageService.clearHistory();
                        _loadData();
                        if (mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Gecmis temizlendi')),
                          );
                        }
                      },
                    ),
                    _buildActionTile(
                      'Onbellegi Temizle',
                      'URL onbellegini sil',
                      Icons.cached,
                      () {
                        widget.apiService.clearCache();
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Onbellek temizlendi')),
                        );
                      },
                    ),
                    const SizedBox(height: 32),

                    // App Info
                    Center(
                      child: Column(
                        children: [
                          const Text(
                            '🛡️ PhishShield TR',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 4),
                          const Text(
                            'Versiyon 2.0.0',
                            style: TextStyle(
                              color: Colors.white38,
                              fontSize: 12,
                            ),
                          ),
                          const SizedBox(height: 8),
                          const Text(
                            'Gercek zamanli phishing korumasi',
                            style: TextStyle(
                              color: Colors.white54,
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 32),
                  ],
                ),
              ),
      ),
    );
  }

  Widget _buildStatsCard() {
    return Container(
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF00d4ff), Color(0xFF00ff88)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
      ),
      padding: const EdgeInsets.all(20),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: [
          _buildStatItem('Toplam', '${_stats['total'] ?? 0}', Icons.search),
          _buildStatItem('Bugun', '${_stats['today'] ?? 0}', Icons.today),
          _buildStatItem(
              'Tehlikeli', '${_stats['danger'] ?? 0}', Icons.warning),
        ],
      ),
    );
  }

  Widget _buildStatItem(String label, String value, IconData icon) {
    return Column(
      children: [
        Icon(icon, color: Colors.white, size: 28),
        const SizedBox(height: 8),
        Text(
          value,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 24,
            fontWeight: FontWeight.bold,
          ),
        ),
        Text(
          label,
          style: const TextStyle(
            color: Colors.white70,
            fontSize: 12,
          ),
        ),
      ],
    );
  }

  Widget _buildSectionTitle(String title) {
    return Text(
      title,
      style: const TextStyle(
        color: Colors.white70,
        fontSize: 14,
        fontWeight: FontWeight.w600,
        letterSpacing: 1,
      ),
    );
  }

  Widget _buildSwitchTile(
    String title,
    String subtitle,
    IconData icon,
    bool value,
    ValueChanged<bool> onChanged,
  ) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      child: SwitchListTile(
        title: Text(
          title,
          style: const TextStyle(color: Colors.white),
        ),
        subtitle: Text(
          subtitle,
          style: const TextStyle(color: Colors.white38, fontSize: 12),
        ),
        secondary: Icon(icon, color: Colors.white54),
        value: value,
        onChanged: onChanged,
        activeColor: const Color(0xFF00d4ff),
      ),
    );
  }

  Widget _buildApiUrlTile() {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.api, color: Colors.white54),
              const SizedBox(width: 12),
              const Text(
                'API Sunucusu',
                style: TextStyle(color: Colors.white),
              ),
            ],
          ),
          const SizedBox(height: 12),
          TextField(
            controller: TextEditingController(text: _settings.apiUrl),
            style: const TextStyle(color: Colors.white, fontSize: 14),
            decoration: InputDecoration(
              hintText: 'http://127.0.0.1:8004',
              hintStyle: TextStyle(color: Colors.white.withOpacity(0.3)),
              filled: true,
              fillColor: Colors.white.withOpacity(0.05),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide.none,
              ),
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 12,
                vertical: 10,
              ),
            ),
            onSubmitted: (value) {
              _updateSettings(_settings.copyWith(apiUrl: value));
            },
          ),
        ],
      ),
    );
  }

  Widget _buildCacheTTLTile() {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.timer, color: Colors.white54),
              const SizedBox(width: 12),
              const Text(
                'Onbellek Suresi',
                style: TextStyle(color: Colors.white),
              ),
              const Spacer(),
              Text(
                '${_settings.cacheTTL ~/ 60} dakika',
                style: const TextStyle(color: Colors.white54),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Slider(
            value: _settings.cacheTTL.toDouble(),
            min: 60,
            max: 600,
            divisions: 9,
            activeColor: const Color(0xFF00d4ff),
            inactiveColor: Colors.white.withOpacity(0.2),
            onChanged: (value) {
              _updateSettings(_settings.copyWith(cacheTTL: value.toInt()));
            },
          ),
        ],
      ),
    );
  }

  Widget _buildActionTile(
    String title,
    String subtitle,
    IconData icon,
    VoidCallback onTap,
  ) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      child: ListTile(
        leading: Icon(icon, color: Colors.white54),
        title: Text(
          title,
          style: const TextStyle(color: Colors.white),
        ),
        subtitle: Text(
          subtitle,
          style: const TextStyle(color: Colors.white38, fontSize: 12),
        ),
        trailing: const Icon(
          Icons.chevron_right,
          color: Colors.white24,
        ),
        onTap: onTap,
      ),
    );
  }
}
