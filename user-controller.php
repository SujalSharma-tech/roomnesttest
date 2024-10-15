<?php

require_once('./database.php');

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\JWTExceptionWithPayloadInterface;

header('Content-Type: application/json');
class userController
{
    private $conn;
    public function __construct($conn)
    {
        // $db = new Database();
        // $this->conn = $db->getConnection();
        $this->conn = $conn;
    }


    private function generateToken($userId, $email)
    {

        $issuedAt = time();
        $secretkey = "secret";
        $expirationTime = $issuedAt + 3600;
        $payload = array(
            'iat' => $issuedAt,
            'exp' => $expirationTime,
            'data' => array(
                "id" => $userId,
                "email" => $email
            )
        );

        $token =  JWT::encode($payload, $secretkey, "HS256");
        setcookie("token", $token, $expirationTime, "/");
        return $token;
    }


    private function decodeToken($token)
    {
        $secretkey = "secret";
        try {
            $decoded = JWT::decode($token, new Key($secretkey, 'HS256'));
            return $decoded->data;
        } catch (JWTExceptionWithPayloadInterface $e) {
            echo json_encode(["success" => false, "message" => $e]);
        }
    }

    public function register($first_name, $last_name, $email, $password)
    {
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->conn->prepare("SELECT * FROM users where email=?");
        $stmt->bind("s",$email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows() > 0) {
            echo json_encode(["success" => false, "message" => "User already exists"]);
        } else {
            $stmt = $this->conn->prepare("INSERT INTO users (first_name,last_name,email,password) VALUES(?,?,?,?)");
            $stmt->bind("ssss",$first_name, $last_name, $email, $hashed_password);
            if ($stmt->execute()) {
                $currId = $this->conn->insert_id;
                $userId = md5($currId);
                $stmt = $this->conn->prepare("UPDATE users SET user_id=? WHERE id=?");
                $stmt->execute([$userId, $currId]);
                $token = userController::generateToken($userId, $email);
                if ($token) {
                    echo json_encode([
                        "success" => true,
                        "message" => "User Successfully Registered",
                        "data" => $userId,
                        "token" => $token
                    ]);
                } else {
                    echo json_encode([
                        "success" => false,
                        "message" => "Failed to generate token"
                    ]);
                }
            }
        }
    }

    public function login($email, $password)
    {
        $stmt = $this->conn->prepare("SELECT * FROM users where email=?");
        $stmt->bind("s",$email);
        $stmt->execute();
        $data = $stmt->get_result()->fetch_array(MYSQLI_ASSOC);
        if ($data) {
            if (password_verify($password, $data['password'])) {
                $token = userController::generateToken($data['user_id'], $email);
                echo json_encode([
                    "success" => true,
                    "message" => "Login Successful",
                    "token" => $token
                ]);
            } else {
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid Password"
                ]);
            }
        } else {
            echo json_encode([
                "success" => false,
                "message" => "User not found"
            ]);
        }
    }


    public function getmyprofile()
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = userController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("SELECT id, first_name, last_name, email FROM users Where user_id=?");
                $stmt->bind("s",$userId);
                $stmt->execute();
                $data = $stmt->get_result()->fetch_array(MYSQLI_ASSOC);
                echo json_encode([
                    "success" => true,
                    "data" => $data
                ]);
            }
        } else {
            echo json_encode([
                "success" => false,
                "message" => "Token not found"
            ]);
        }
    }
}
