<?php
require_once 'config.php';




// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = "";
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// Processing form data when the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
 
    // Check if username is empty
    if (empty(trim($_POST["user"]))) {
        $username_err = "Please enter a username.";
    } else {
        $username = trim($_POST["user"]);
    }
    
    // Check if the password is empty
    if (empty(trim($_POST["pass"]))) {
        $password_err = "Please enter your password.";
    } else {
        $password = trim($_POST["pass"]);
    }
    
    // Validate credentials
    if (empty($username_err) && empty($password_err)) {
        // Prepare a select statement
        $sql = "SELECT * FROM users WHERE username = ?";
        
        if ($stmt = $mysqli->prepare($sql)) {
            // Bind variables to the prepared statement as parameters
            $stmt->bind_param("s", $param_username);
            
            // Set parameters
            $param_username = $username;
            
            // Attempt to execute the prepared statement
            if ($stmt->execute()) {
                // Store result
                $stmt->store_result();
                
                // Check if the username exists, if yes then verify the password
                if ($stmt->num_rows == 1) {                    
                    // Bind result variables
                    $result = $stmt->bind_result($id, $username, $password, $token);
                
                    if ($stmt->fetch()) {
                        if (password_verify($password, $hashed_password)) {
                            // Password is correct, so start a new session
                            session_start();
                            
                            // Generate token
                            $token = bin2hex(random_bytes(16));
                            
                            // Update token in the database
                            $sql = "UPDATE `users` SET token = ? WHERE id = ?";
                            if ($stmt = $mysqli->prepare($sql)) {
                                // Bind variables to the prepared statement as parameters
                                $stmt->bind_param("si", $param_username);
                                
                                // Set parameters
                                $param_username=$username;
                                
                                // Attempt to execute the prepared statement
                                if ($stmt->execute()) {
                                    // Token updated successfully, so set the cookie and redirect to the dashboard
                                    setcookie("token", $token, time() + 3600);
                                    header('Location: dashboard.php');
                                    
                                } else {
                                    error_log("Execution of prepared statement failed: " . $stmt->error);

                                    echo "Oops! Something went wrong. Please try again later.";
                                }
                            }
                        } else {
                            // Password is incorrect, display an error message
                            $password_err = "The password you entered was not valid.";
                        }
                    }
                } else {
                    // Username doesn't exist, display an error message
                    $username_err = "No account found with that username.";
                }
            } else {
                echo "Oops! Something went wrong. Please try again later.";
            }
        }
    }
}
?>
  <div class="login">
			<h1>Login</h1>
			<form action="./Pages//login.php" method="POST">
				<label for="username">
					<i class="fas fa-user"></i>
				</label>
				<input type="text" name="user" placeholder="Username" id="user" required>
				<label for="password">
					<i class="fas fa-lock"></i>
				</label>
				<input type="password" name="pass" placeholder="Password" id="pass" required>
				<input type="submit" value="Login">
			</form>
		</div>