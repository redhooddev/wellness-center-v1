<?php
require_once '../include/db.php';

if($_SERVER['REQUEST_METHOD'] === 'POST'){
    $firstName = trim($_POST['first_name']);
    $lastName = trim($_POST['last_name']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $username = trim($_POST['username']);

    // Check if email exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$username]);

    if($stmt->fetch()){
        header('Location: ../register.html?error=username_exists');
        exit;
    } else {
        $hashedPassword - password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users(first_name, last_name, email, username, password_hash) VALUES (?, ?, ?, ?, ?)");

        if($stmt->execute([$firstName, $lastName, $email, $username, $hashedPassword])){
            header('Location: ../login.html?registered=1');
            exit;
        } else {
            header('Location: ../register.html?error=registration_failed');
            exit;
        }
    }
}
?>