<?php
// File: index.php
 
session_start();
require_once 'db.php';
 
// Initialize database connection
 $database = new Database();
 $db = $database->getConnection();
 
// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}
 
// Get current user data
function getCurrentUser($db) {
    if (!isLoggedIn()) return null;
 
    try {
        $query = "SELECT * FROM users WHERE id = :id";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':id', $_SESSION['user_id']);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch(PDOException $exception) {
        return null;
    }
}
 
// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle login
    if (isset($_POST['login'])) {
        $email = $_POST['email'];
        $password = $_POST['password'];
 
        try {
            $query = "SELECT * FROM users WHERE email = :email";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
 
            if ($stmt->rowCount() > 0) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if (password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    header('Location: index.php');
                    exit;
                } else {
                    $login_error = "Invalid password";
                }
            } else {
                $login_error = "User not found";
            }
        } catch(PDOException $exception) {
            $login_error = "Error: " . $exception->getMessage();
        }
    }
 
    // Handle signup
    if (isset($_POST['signup'])) {
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
 
        try {
            $query = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':username', $username);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':password', $password);
 
            if ($stmt->execute()) {
                $signup_success = "Account created successfully. Please login.";
            } else {
                $signup_error = "Unable to create account";
            }
        } catch(PDOException $exception) {
            $signup_error = "Error: " . $exception->getMessage();
        }
    }
 
    // Handle send money
    if (isset($_POST['send_money']) && isLoggedIn()) {
        $receiver_email = $_POST['receiver_email'];
        $amount = $_POST['amount'];
        $description = $_POST['description'];
        $sender_id = $_SESSION['user_id'];
 
        try {
            // Get sender data
            $query = "SELECT * FROM users WHERE id = :id";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':id', $sender_id);
            $stmt->execute();
            $sender = $stmt->fetch(PDO::FETCH_ASSOC);
 
            // Get receiver data
            $query = "SELECT * FROM users WHERE email = :email";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':email', $receiver_email);
            $stmt->execute();
 
            if ($stmt->rowCount() > 0) {
                $receiver = $stmt->fetch(PDO::FETCH_ASSOC);
 
                // Check if sender has enough balance
                if ($sender['balance'] >= $amount) {
                    // Start transaction
                    $db->beginTransaction();
 
                    // Update sender balance
                    $query = "UPDATE users SET balance = balance - :amount WHERE id = :id";
                    $stmt = $db->prepare($query);
                    $stmt->bindParam(':amount', $amount);
                    $stmt->bindParam(':id', $sender_id);
                    $stmt->execute();
 
                    // Update receiver balance
                    $query = "UPDATE users SET balance = balance + :amount WHERE id = :id";
                    $stmt = $db->prepare($query);
                    $stmt->bindParam(':amount', $amount);
                    $stmt->bindParam(':id', $receiver['id']);
                    $stmt->execute();
 
                    // Record transaction
                    $query = "INSERT INTO transactions (sender_id, receiver_id, amount, description, status) 
                              VALUES (:sender_id, :receiver_id, :amount, :description, 'completed')";
                    $stmt = $db->prepare($query);
                    $stmt->bindParam(':sender_id', $sender_id);
                    $stmt->bindParam(':receiver_id', $receiver['id']);
                    $stmt->bindParam(':amount', $amount);
                    $stmt->bindParam(':description', $description);
                    $stmt->execute();
 
                    // Commit transaction
                    $db->commit();
 
                    $send_success = "Money sent successfully!";
                } else {
                    $send_error = "Insufficient balance";
                }
            } else {
                $send_error = "Receiver not found";
            }
        } catch(PDOException $exception) {
            $db->rollBack();
            $send_error = "Error: " . $exception->getMessage();
        }
    }
 
    // Handle add funds
    if (isset($_POST['add_funds']) && isLoggedIn()) {
        $amount = $_POST['amount'];
        $user_id = $_SESSION['user_id'];
 
        try {
            // Update user balance
            $query = "UPDATE users SET balance = balance + :amount WHERE id = :id";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':amount', $amount);
            $stmt->bindParam(':id', $user_id);
 
            if ($stmt->execute()) {
                $add_funds_success = "Funds added successfully!";
            } else {
                $add_funds_error = "Unable to add funds";
            }
        } catch(PDOException $exception) {
            $add_funds_error = "Error: " . $exception->getMessage();
        }
    }
 
    // Handle logout
    if (isset($_POST['logout'])) {
        session_destroy();
        header('Location: index.php');
        exit;
    }
}
 
// Get current user
 $current_user = getCurrentUser($db);
 
// Get transaction history for current user
function getTransactionHistory($db, $user_id) {
    try {
        $query = "SELECT t.*, 
                         u1.username as sender_name, 
                         u2.username as receiver_name 
                  FROM transactions t
                  JOIN users u1 ON t.sender_id = u1.id
                  JOIN users u2 ON t.receiver_id = u2.id
                  WHERE t.sender_id = :user_id OR t.receiver_id = :user_id
                  ORDER BY t.created_at DESC";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch(PDOException $exception) {
        return [];
    }
}
 
 $transactions = isLoggedIn() ? getTransactionHistory($db, $_SESSION['user_id']) : [];
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PayPal Clone - Secure Online Payment Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
 
        .container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
 
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
 
        .card-header {
            background-color: #0070ba;
            color: white;
            border-bottom: none;
            padding: 1rem;
            font-weight: 600;
        }
 
        .btn-primary {
            background-color: #0070ba;
            border-color: #0070ba;
        }
 
        .btn-primary:hover {
            background-color: #005ea6;
            border-color: #005ea6;
        }
 
        .navbar {
            background-color: #003087 !important;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
 
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }
 
        .hero-section {
            background-color: rgba(255, 255, 255, 0.9);
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
 
        .balance-card {
            background: linear-gradient(135deg, #005ea6 0%, #0070ba 100%);
            color: white;
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 20px;
        }
 
        .transaction-item {
            border-bottom: 1px solid #eee;
            padding: 0.75rem 0;
        }
 
        .transaction-item:last-child {
            border-bottom: none;
        }
 
        .amount-positive {
            color: #28a745;
            font-weight: 600;
        }
 
        .amount-negative {
            color: #dc3545;
            font-weight: 600;
        }
 
        .form-control:focus {
            border-color: #0070ba;
            box-shadow: 0 0 0 0.25rem rgba(0, 112, 186, 0.25);
        }
 
        .alert {
            border-radius: 10px;
        }
 
        .feature-icon {
            font-size: 2.5rem;
            color: #0070ba;
            margin-bottom: 1rem;
        }
 
        .footer {
            background-color: #003087;
            color: white;
            padding: 2rem 0;
            margin-top: 3rem;
        }
 
        .demo-accounts {
            background-color: rgba(255, 255, 255, 0.9);
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="index.php">
                <i class="bi bi-wallet2"></i> PayClone
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <?php if (isLoggedIn()): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="index.php#dashboard">Dashboard</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="index.php#send">Send Money</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="index.php#transactions">Transactions</a>
                        </li>
                        <li class="nav-item">
                            <form method="post" class="d-inline">
                                <button type="submit" name="logout" class="btn btn-outline-light btn-sm">Logout</button>
                            </form>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="index.php#login">Login</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="index.php#signup">Sign Up</a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>
 
    <div class="container">
        <?php if (!isLoggedIn()): ?>
            <!-- Demo Accounts Section -->
            <div class="demo-accounts">
                <h4 class="text-center mb-3">Demo Accounts</h4>
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5>Admin Account</h5>
                                <p><strong>Email:</strong> admin@example.com</p>
                                <p><strong>Password:</strong> admin123</p>
                                <p><strong>Balance:</strong> $5000.00</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5>Test Account</h5>
                                <p><strong>Email:</strong> test@example.com</p>
                                <p><strong>Password:</strong> test123</p>
                                <p><strong>Balance:</strong> $1000.00</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
 
            <!-- Hero Section -->
            <div class="hero-section text-center">
                <h1 class="display-4 fw-bold mb-4">Secure Online Payment Platform</h1>
                <p class="lead mb-4">Send, receive, and manage your money with our secure and easy-to-use payment system.</p>
                <div class="d-flex justify-content-center gap-3">
                    <a href="#login" class="btn btn-primary btn-lg">Login</a>
                    <a href="#signup" class="btn btn-outline-primary btn-lg">Sign Up</a>
                </div>
            </div>
 
            <!-- Features Section -->
            <div class="row mb-5">
                <div class="col-md-4 mb-4">
                    <div class="card h-100 text-center p-4">
                        <div class="feature-icon">
                            <i class="bi bi-shield-check"></i>
                        </div>
                        <h3>Secure Transactions</h3>
                        <p>Your money and data are protected with industry-leading security measures.</p>
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="card h-100 text-center p-4">
                        <div class="feature-icon">
                            <i class="bi bi-lightning-charge"></i>
                        </div>
                        <h3>Instant Transfers</h3>
                        <p>Send and receive money instantly with just a few clicks.</p>
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="card h-100 text-center p-4">
                        <div class="feature-icon">
                            <i class="bi bi-globe"></i>
                        </div>
                        <h3>Global Access</h3>
                        <p>Access your money from anywhere in the world, anytime.</p>
                    </div>
                </div>
            </div>
 
            <!-- Login Section -->
            <div id="login" class="row justify-content-center mb-5">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Login to Your Account</h4>
                        </div>
                        <div class="card-body p-4">
                            <?php if (isset($login_error)): ?>
                                <div class="alert alert-danger"><?php echo $login_error; ?></div>
                            <?php endif; ?>
                            <form method="post">
                                <div class="mb-3">
                                    <label for="email" class="form-label">Email</label>
                                    <input type="email" class="form-control" id="email" name="email" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Password</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" name="login" class="btn btn-primary">Login</button>
                                </div>
                            </form>
                            <div class="text-center mt-3">
                                <p>Don't have an account? <a href="#signup">Sign Up</a></p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
 
            <!-- Signup Section -->
            <div id="signup" class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Create Your Account</h4>
                        </div>
                        <div class="card-body p-4">
                            <?php if (isset($signup_success)): ?>
                                <div class="alert alert-success"><?php echo $signup_success; ?></div>
                            <?php endif; ?>
                            <?php if (isset($signup_error)): ?>
                                <div class="alert alert-danger"><?php echo $signup_error; ?></div>
                            <?php endif; ?>
                            <form method="post">
                                <div class="mb-3">
                                    <label for="username" class="form-label">Username</label>
                                    <input type="text" class="form-control" id="username" name="username" required>
                                </div>
                                <div class="mb-3">
                                    <label for="email" class="form-label">Email</label>
                                    <input type="email" class="form-control" id="email" name="email" required>
                                </div>
                                <div class="mb-3">
                                    <label for="password" class="form-label">Password</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" name="signup" class="btn btn-primary">Sign Up</button>
                                </div>
                            </form>
                            <div class="text-center mt-3">
                                <p>Already have an account? <a href="#login">Login</a></p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <!-- Dashboard Section -->
            <div id="dashboard" class="row mb-4">
                <div class="col-md-12">
                    <h2 class="text-white mb-4">Welcome, <?php echo htmlspecialchars($current_user['username']); ?>!</h2>
                </div>
                <div class="col-md-4">
                    <div class="balance-card">
                        <h5>Current Balance</h5>
                        <h2>$<?php echo number_format($current_user['balance'], 2); ?></h2>
                    </div>
                </div>
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Quick Actions</h4>
                        </div>
                        <div class="card-body">
                            <div class="d-flex gap-3">
                                <a href="#send" class="btn btn-primary">Send Money</a>
                                <a href="#add-funds" class="btn btn-success">Add Funds</a>
                                <a href="#transactions" class="btn btn-info">View Transactions</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
 
            <!-- Send Money Section -->
            <div id="send" class="row mb-4">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Send Money</h4>
                        </div>
                        <div class="card-body p-4">
                            <?php if (isset($send_success)): ?>
                                <div class="alert alert-success"><?php echo $send_success; ?></div>
                            <?php endif; ?>
                            <?php if (isset($send_error)): ?>
                                <div class="alert alert-danger"><?php echo $send_error; ?></div>
                            <?php endif; ?>
                            <form method="post">
                                <div class="mb-3">
                                    <label for="receiver_email" class="form-label">Recipient's Email</label>
                                    <input type="email" class="form-control" id="receiver_email" name="receiver_email" required>
                                </div>
                                <div class="mb-3">
                                    <label for="amount" class="form-label">Amount ($)</label>
                                    <input type="number" class="form-control" id="amount" name="amount" min="0.01" step="0.01" required>
                                </div>
                                <div class="mb-3">
                                    <label for="description" class="form-label">Description (Optional)</label>
                                    <input type="text" class="form-control" id="description" name="description">
                                </div>
                                <div class="d-grid">
                                    <button type="submit" name="send_money" class="btn btn-primary">Send Money</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Add Funds</h4>
                        </div>
                        <div class="card-body p-4">
                            <?php if (isset($add_funds_success)): ?>
                                <div class="alert alert-success"><?php echo $add_funds_success; ?></div>
                            <?php endif; ?>
                            <?php if (isset($add_funds_error)): ?>
                                <div class="alert alert-danger"><?php echo $add_funds_error; ?></div>
                            <?php endif; ?>
                            <form method="post">
                                <div class="mb-3">
                                    <label for="amount" class="form-label">Amount ($)</label>
                                    <input type="number" class="form-control" id="amount" name="amount" min="0.01" step="0.01" required>
                                </div>
                                <div class="mb-3">
                                    <label for="payment_method" class="form-label">Payment Method</label>
                                    <select class="form-select" id="payment_method">
                                        <option value="credit_card">Credit Card</option>
                                        <option value="debit_card">Debit Card</option>
                                        <option value="bank_transfer">Bank Transfer</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label for="card_number" class="form-label">Card Number</label>
                                    <input type="text" class="form-control" id="card_number" placeholder="1234 5678 9012 3456">
                                </div>
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <label for="expiry_date" class="form-label">Expiry Date</label>
                                        <input type="text" class="form-control" id="expiry_date" placeholder="MM/YY">
                                    </div>
                                    <div class="col-md-6">
                                        <label for="cvv" class="form-label">CVV</label>
                                        <input type="text" class="form-control" id="cvv" placeholder="123">
                                    </div>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" name="add_funds" class="btn btn-success">Add Funds</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
 
            <!-- Transactions Section -->
            <div id="transactions" class="row">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="mb-0">Transaction History</h4>
                        </div>
                        <div class="card-body">
                            <?php if (empty($transactions)): ?>
                                <p class="text-center">No transactions found.</p>
                            <?php else: ?>
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Date</th>
                                                <th>Description</th>
                                                <th>From/To</th>
                                                <th>Amount</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($transactions as $transaction): ?>
                                                <tr>
                                                    <td><?php echo date('M d, Y H:i', strtotime($transaction['created_at'])); ?></td>
                                                    <td><?php echo htmlspecialchars($transaction['description'] ?: 'Money Transfer'); ?></td>
                                                    <td>
                                                        <?php 
                                                        if ($transaction['sender_id'] == $_SESSION['user_id']) {
                                                            echo 'To: ' . htmlspecialchars($transaction['receiver_name']);
                                                        } else {
                                                            echo 'From: ' . htmlspecialchars($transaction['sender_name']);
                                                        }
                                                        ?>
                                                    </td>
                                                    <td class="<?php echo $transaction['sender_id'] == $_SESSION['user_id'] ? 'amount-negative' : 'amount-positive'; ?>">
                                                        <?php 
                                                        echo $transaction['sender_id'] == $_SESSION['user_id'] ? '-' : '+';
                                                        echo '$' . number_format($transaction['amount'], 2);
                                                        ?>
                                                    </td>
                                                    <td>
                                                        <span class="badge bg-<?php echo $transaction['status'] == 'completed' ? 'success' : 'warning'; ?>">
                                                            <?php echo ucfirst($transaction['status']); ?>
                                                        </span>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>
 
    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="col-md-4">
                    <h5>PayClone</h5>
                    <p>A secure and easy-to-use online payment platform.</p>
                </div>
                <div class="col-md-4">
                    <h5>Quick Links</h5>
                    <ul class="list-unstyled">
                        <li><a href="#" class="text-white">About Us</a></li>
                        <li><a href="#" class="text-white">Contact</a></li>
                        <li><a href="#" class="text-white">Privacy Policy</a></li>
                        <li><a href="#" class="text-white">Terms of Service</a></li>
                    </ul>
                </div>
                <div class="col-md-4">
                    <h5>Contact Us</h5>
                    <p>Email: support@payclone.com</p>
                    <p>Phone: +1 (555) 123-4567</p>
                </div>
            </div>
            <hr class="bg-white my-4">
            <div class="text-center">
                <p>&copy; <?php echo date('Y'); ?> PayClone. All rights reserved.</p>
            </div>
        </div>
    </footer>
 
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
 
        // Format card number input
        const cardNumberInput = document.getElementById('card_number');
        if (cardNumberInput) {
            cardNumberInput.addEventListener('input', function() {
                let value = this.value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
                let formattedValue = value.match(/.{1,4}/g)?.join(' ') || value;
                this.value = formattedValue;
            });
        }
 
        // Format expiry date input
        const expiryDateInput = document.getElementById('expiry_date');
        if (expiryDateInput) {
            expiryDateInput.addEventListener('input', function() {
                let value = this.value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
                if (value.length >= 2) {
                    value = value.substring(0, 2) + '/' + value.substring(2, 4);
                }
                this.value = value;
            });
        }
 
        // Format CVV input
        const cvvInput = document.getElementById('cvv');
        if (cvvInput) {
            cvvInput.addEventListener('input', function() {
                this.value = this.value.replace(/\s+/g, '').replace(/[^0-9]/gi, '').substring(0, 3);
            });
        }
    </script>
</body>
</html>
Syntax highlighting powered by GeSHi
Help Guide | License
