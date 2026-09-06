/**
 * PhishShield TR - Mobile App
 * Main Entry Point
 */

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'services/services.dart';
import 'screens/screens.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Set system UI style
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
    ),
  );

  // Initialize services
  final storageService = StorageService();
  await storageService.init();

  final apiService = ApiService();

  runApp(
    PhishShieldApp(
      storageService: storageService,
      apiService: apiService,
    ),
  );
}

class PhishShieldApp extends StatelessWidget {
  final StorageService storageService;
  final ApiService apiService;

  const PhishShieldApp({
    super.key,
    required this.storageService,
    required this.apiService,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PhishShield TR',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        primaryColor: const Color(0xFF00d4ff),
        scaffoldBackgroundColor: const Color(0xFF1a1a2e),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00d4ff),
          secondary: Color(0xFF00ff88),
          surface: Color(0xFF16213e),
          error: Color(0xFFF44336),
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF1a1a2e),
          foregroundColor: Colors.white,
          elevation: 0,
        ),
        cardTheme: CardTheme(
          color: Colors.white.withOpacity(0.1),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF00d4ff),
            foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
        ),
      ),
      home: MainScreen(
        storageService: storageService,
        apiService: apiService,
      ),
    );
  }
}

class MainScreen extends StatefulWidget {
  final StorageService storageService;
  final ApiService apiService;

  const MainScreen({
    super.key,
    required this.storageService,
    required this.apiService,
  });

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  int _currentIndex = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: IndexedStack(
        index: _currentIndex,
        children: [
          ScannerScreen(
            apiService: widget.apiService,
            storageService: widget.storageService,
          ),
          HistoryScreen(
            storageService: widget.storageService,
            apiService: widget.apiService,
          ),
          AlertsScreen(
            storageService: widget.storageService,
          ),
          ProfileScreen(
            storageService: widget.storageService,
            apiService: widget.apiService,
          ),
        ],
      ),
      bottomNavigationBar: Container(
        decoration: BoxDecoration(
          color: const Color(0xFF1a1a2e),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.3),
              blurRadius: 10,
              offset: const Offset(0, -5),
            ),
          ],
        ),
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                _buildNavItem(0, Icons.qr_code_scanner, 'Tarayici'),
                _buildNavItem(1, Icons.history, 'Gecmis'),
                _buildNavItem(2, Icons.notifications, 'Uyarlar'),
                _buildNavItem(3, Icons.person, 'Ayarlar'),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildNavItem(int index, IconData icon, String label) {
    final isSelected = _currentIndex == index;

    return InkWell(
      onTap: () => setState(() => _currentIndex = index),
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        decoration: BoxDecoration(
          color: isSelected
              ? const Color(0xFF00d4ff).withOpacity(0.2)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              color: isSelected ? const Color(0xFF00d4ff) : Colors.white54,
              size: 24,
            ),
            const SizedBox(height: 4),
            Text(
              label,
              style: TextStyle(
                color: isSelected ? const Color(0xFF00d4ff) : Colors.white54,
                fontSize: 11,
                fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
