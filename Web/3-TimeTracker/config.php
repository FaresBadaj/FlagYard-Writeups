<?php
// TimeTracker Pro Configuration
define('APP_NAME', 'TimeTracker Pro');
define('APP_VERSION', '1.2.3');
define('DATA_DIR', 'data');

// Company settings
define('COMPANY_NAME', 'Acme Corp');
define('STANDARD_HOURS', 40);
define('OVERTIME_RATE', 1.5);

// Default timezone
date_default_timezone_set('America/New_York');

// Error reporting (disable in production)
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'error.log');

// Ensure data directory exists
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}
?> 