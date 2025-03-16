<?php
session_start();
require 'db.php'; // Database connection

// Initialize error message variable
$error_message = "";

// Brute Force Protection: Limit login attempts per session
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}

if ($_SESSION['login_attempts'] >= 5) {
    $error_message = "Too many failed attempts. Try again later.";
} else if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // Validate input
    if (!empty($email) && !empty($password)) {
        // Fetch user from the database
        $stmt = $conn->prepare("SELECT `id`, `email`, `password`, `role` FROM `users` WHERE `email` = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $email, $hashed_password, $role);
            $stmt->fetch();

            // Verify password
            if (password_verify($password, $hashed_password)) {
                $_SESSION['user_id'] = $id;
                $_SESSION['email'] = $email;
                $_SESSION['role'] = $role;
                $_SESSION['login_attempts'] = 0; // Reset login attempts
                
                // Redirect to the dashboard
                header("Location: dashboard.php");
                exit();
            } else {
                $_SESSION['login_attempts']++;
                $error_message = "Invalid email or password.";
            }
        } else {
            $_SESSION['login_attempts']++;
            $error_message = "Invalid email or password.";
        }

        $stmt->close();
    } else {
        $error_message = "Please enter both email and password.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GateKeeper - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="height: 100vh;">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h2 class="text-center">Login to GateKeeper</h2>

                        <div class="alert alert-info text-center">
                            <h5>Demo Credentials</h5>
                            <p><strong>Admin:</strong> admin@example.com | <strong>Password:</strong> demo123</p>
                            <p><strong>Manager:</strong> manager@example.com | <strong>Password:</strong> demo123</p>
                            <p><strong>Employee:</strong> employee@example.com | <strong>Password:</strong> demo123</p>
                        </div>

                        <?php if (!empty($error_message)): ?>
                            <div class="alert alert-danger text-center">
                                <?php echo $error_message; ?>
                            </div>
                        <?php endif; ?>

                        <form action="login.php" method="POST">
                            <div class="mb-3">
                                <label for="email" class="form-label">Email Address</label>
                                <input type="email" name="email" class="form-control" required>
                            </div>

                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" name="password" class="form-control" required>
                            </div>

                            <button type="submit" class="btn btn-primary w-100">Login</button>
                        </form>

                        <div class="text-center mt-3">
                            <p>Don't have an account? <a href="signup.php">Sign Up</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
