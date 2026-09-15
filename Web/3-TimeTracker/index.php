<?php
session_start();
require_once 'config.php';

// Simple authentication
if (!isset($_SESSION['user_id'])) {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        // Simple login check
        if ($_POST['username'] === 'admin' && $_POST['password'] === 'admin123') {
            $_SESSION['user_id'] = 1;
            $_SESSION['username'] = 'admin';
        } else {
            $error = "Invalid credentials";
        }
    }
    
    if (!isset($_SESSION['user_id'])) {
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>TimeTracker Pro - Login</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="row justify-content-center">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h4>TimeTracker Pro - Employee Login</h4>
                            </div>
                            <div class="card-body">
                                <?php if (isset($error)): ?>
                                    <div class="alert alert-danger"><?php echo $error; ?></div>
                                <?php endif; ?>
                                <form method="post">
                                    <div class="mb-3">
                                        <label class="form-label">Username</label>
                                        <input type="text" name="username" class="form-control" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Password</label>
                                        <input type="password" name="password" class="form-control" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Login</button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

// Initialize data file
$data_file = 'data/timesheets.json';
if (!file_exists($data_file)) {
    $sample_data = [
        ['id' => 1, 'employee_name' => 'John Smith', 'project_name' => 'Website Redesign', 'hours' => 8.5, 'date' => '2024-01-15', 'description' => 'Frontend development'],
        ['id' => 2, 'employee_name' => 'Jane Doe', 'project_name' => 'Mobile App', 'hours' => 7.0, 'date' => '2024-01-15', 'description' => 'API integration'],
        ['id' => 3, 'employee_name' => 'Bob Johnson', 'project_name' => 'Database Migration', 'hours' => 6.5, 'date' => '2024-01-16', 'description' => 'Data cleanup']
    ];
    file_put_contents($data_file, json_encode($sample_data, JSON_PRETTY_PRINT));
}

// Load data
$timesheets = json_decode(file_get_contents($data_file), true);

// Handle different actions
$action = $_GET['action'] ?? 'dashboard';

switch ($action) {
    case 'add_timesheet':
        if ($_POST) {
            $new_id = max(array_column($timesheets, 'id')) + 1;
            $new_entry = [
                'id' => $new_id,
                'employee_name' => $_POST['employee_name'],
                'project_name' => $_POST['project_name'],
                'hours' => floatval($_POST['hours']),
                'date' => $_POST['date'],
                'description' => $_POST['description']
            ];
            $timesheets[] = $new_entry;
            file_put_contents($data_file, json_encode($timesheets, JSON_PRETTY_PRINT));
            header('Location: index.php');
            exit;
        }
        break;
        
    case 'reports':
        $report_type = $_GET['type'] ?? 'summary';
        $period = $_GET['period'] ?? 'week';
        
        switch ($report_type) {
            case 'summary':
                $results = [];
                foreach ($timesheets as $entry) {
                    $name = $entry['employee_name'];
                    if (!isset($results[$name])) {
                        $results[$name] = ['employee_name' => $name, 'total_hours' => 0];
                    }
                    $results[$name]['total_hours'] += $entry['hours'];
                }
                $results = array_values($results);
                break;
            case 'project':
                $results = [];
                foreach ($timesheets as $entry) {
                    $project = $entry['project_name'];
                    if (!isset($results[$project])) {
                        $results[$project] = ['project_name' => $project, 'total_hours' => 0];
                    }
                    $results[$project]['total_hours'] += $entry['hours'];
                }
                $results = array_values($results);
                break;
            case 'detailed':
                $results = $timesheets;
                usort($results, function($a, $b) {
                    return strtotime($b['date']) - strtotime($a['date']);
                });
                break;
            default:
                $results = $timesheets;
        }
        break;
        
    case 'export':
        $format = $_GET['format'] ?? 'csv';
        $export_data = $timesheets;
        
        if ($format === 'csv') {
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="timesheet_report.csv"');
            
            if (!empty($export_data)) {
                echo implode(',', array_keys($export_data[0])) . "\n";
                foreach ($export_data as $row) {
                    echo implode(',', array_map(function($val) {
                        return '"' . str_replace('"', '""', $val) . '"';
                    }, $row)) . "\n";
                }
            }
            exit;
        }
        break;
        
    case 'process_data':
        if (isset($_GET['processor']) && isset($_GET['data'])) {
            $processor = $_GET['processor'];
            $data = $_GET['data'];
            
            if ($processor === 'calculate_overtime') {
                $overtime = max(0, floatval($data) - 40);
                echo "Overtime hours: " . $overtime;
            } elseif ($processor === 'format_currency') {
                echo "$" . number_format(floatval($data), 2);
            } elseif ($processor === 'validate_hours') {
                echo (floatval($data) >= 0 && floatval($data) <= 24) ? "Valid" : "Invalid";
            } else {
                $processor($data);
            }
        }
        break;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>TimeTracker Pro - Employee Timesheet Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">TimeTracker Pro</a>
            <div class="navbar-nav">
                <a class="nav-link" href="index.php">Dashboard</a>
                <a class="nav-link" href="?action=reports">Reports</a>
                <a class="nav-link" href="?action=export">Export</a>
                <a class="nav-link" href="logout.php">Logout (<?php echo $_SESSION['username']; ?>)</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <?php if ($action === 'dashboard'): ?>
            <h2>Employee Timesheet Dashboard</h2>
            
            <div class="row mb-4">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5>Add New Timesheet Entry</h5>
                        </div>
                        <div class="card-body">
                            <form method="post" action="?action=add_timesheet">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label class="form-label">Employee Name</label>
                                            <input type="text" name="employee_name" class="form-control" required>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label class="form-label">Project Name</label>
                                            <input type="text" name="project_name" class="form-control" required>
                                        </div>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label class="form-label">Hours Worked</label>
                                            <input type="number" step="0.5" name="hours" class="form-control" required>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label class="form-label">Date</label>
                                            <input type="date" name="date" class="form-control" required>
                                        </div>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Description</label>
                                    <textarea name="description" class="form-control" rows="3"></textarea>
                                </div>
                                <button type="submit" class="btn btn-primary">Add Entry</button>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5>Quick Stats</h5>
                        </div>
                        <div class="card-body">
                            <?php
                            $total_hours = array_sum(array_column($timesheets, 'hours'));
                            $total_employees = count(array_unique(array_column($timesheets, 'employee_name')));
                            $total_projects = count(array_unique(array_column($timesheets, 'project_name')));
                            ?>
                            <p><strong>Total Hours:</strong> <?php echo $total_hours; ?></p>
                            <p><strong>Active Employees:</strong> <?php echo $total_employees; ?></p>
                            <p><strong>Active Projects:</strong> <?php echo $total_projects; ?></p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h5>Recent Entries</h5>
                </div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Employee</th>
                                <th>Project</th>
                                <th>Hours</th>
                                <th>Date</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $recent = array_slice(array_reverse($timesheets), 0, 10);
                            foreach ($recent as $entry):
                            ?>
                            <tr>
                                <td><?php echo htmlspecialchars($entry['employee_name']); ?></td>
                                <td><?php echo htmlspecialchars($entry['project_name']); ?></td>
                                <td><?php echo $entry['hours']; ?></td>
                                <td><?php echo $entry['date']; ?></td>
                                <td><?php echo htmlspecialchars($entry['description']); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        <?php elseif ($action === 'reports'): ?>
            <h2>Reports</h2>
            
            <div class="row mb-3">
                <div class="col-md-12">
                    <div class="btn-group" role="group">
                        <a href="?action=reports&type=summary" class="btn btn-outline-primary">Employee Summary</a>
                        <a href="?action=reports&type=project" class="btn btn-outline-primary">Project Summary</a>
                        <a href="?action=reports&type=detailed" class="btn btn-outline-primary">Detailed Report</a>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h5><?php echo ucfirst($report_type); ?> Report</h5>
                </div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <?php if (!empty($results)): ?>
                                    <?php foreach (array_keys($results[0]) as $header): ?>
                                        <th><?php echo ucfirst(str_replace('_', ' ', $header)); ?></th>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($results as $row): ?>
                            <tr>
                                <?php foreach ($row as $value): ?>
                                    <td><?php echo htmlspecialchars($value); ?></td>
                                <?php endforeach; ?>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        <?php elseif ($action === 'export'): ?>
            <h2>Export Data</h2>
            
            <div class="card">
                <div class="card-header">
                    <h5>Export Options</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Quick Exports</h6>
                            <p><a href="?action=export&format=csv" class="btn btn-success">Export All Data (CSV)</a></p>
                            <p><a href="?action=export&format=csv&type=summary" class="btn btn-info">Employee Summary (CSV)</a></p>
                            <p><a href="?action=export&format=csv&type=project" class="btn btn-info">Project Summary (CSV)</a></p>
                        </div>
                        <div class="col-md-6">
                            <h6>Data Processing Tools</h6>
                            <p>Process data before export:</p>
                            <form method="get" action="?action=process_data">
                                <input type="hidden" name="action" value="process_data">
                                <div class="mb-3">
                                    <label class="form-label">Processor</label>
                                    <select name="processor" class="form-select">
                                        <option value="calculate_overtime">Calculate Overtime</option>
                                        <option value="format_currency">Format Currency</option>
                                        <option value="validate_hours">Validate Hours</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Data</label>
                                    <input type="text" name="data" class="form-control" placeholder="Enter value to process">
                                </div>
                                <button type="submit" class="btn btn-primary">Process Data</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
</body>
</html> 