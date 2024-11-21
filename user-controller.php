<?php
header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

header('Access-Control-Allow-Credentials: true');
require_once('./database.php');

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\JWTExceptionWithPayloadInterface;

// header('Content-Type: application/json');
header('Content-Type: application/json, multipart/form-data');

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
        $expirationTime = $issuedAt + 86300;
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
            echo json_encode(["success" => false, "message" => "Token Error or Expired"]);
        }
    }

    public function register($first_name, $last_name, $email, $password)
    {
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->conn->prepare("SELECT * FROM users where email=?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows() > 0) {
            echo json_encode(["success" => false, "message" => "User already exists"]);
        } else {
            $stmt = $this->conn->prepare("INSERT INTO users (first_name,last_name,email,password) VALUES(?,?,?,?)");
            $stmt->bind_param("ssss", $first_name, $last_name, $email, $hashed_password);
            if ($stmt->execute()) {
                $currId = $this->conn->insert_id;
                $userId = md5($currId);
                $stmt = $this->conn->prepare("UPDATE users SET user_id=? WHERE id=?");
                $stmt->bind_param("si", $userId, $currId);
                $stmt->execute();
                $token = userController::generateToken($userId, $email);
                if ($token) {
                    setcookie("token", $token, time() + 86300, "/", "", true, true);

                    $user = [
                        "id" => $userId,
                        "first_name" => $first_name,
                        "last_name" => $last_name,
                        "email" => $email
                    ];
                    echo json_encode([
                        "success" => true,
                        "message" => "User Successfully Registered",
                        "user" => $user,
                    ], JSON_UNESCAPED_SLASHES);
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
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $data = $stmt->get_result()->fetch_array(MYSQLI_ASSOC);
        if ($data) {
            if (password_verify($password, $data['password'])) {
                $token = userController::generateToken($data['user_id'], $email);
                setcookie("token", $token, time() + 86300, "/", "", true, true);
                $user = [
                    "id" => $data['user_id'],
                    "first_name" => $data['first_name'],
                    "last_name" => $data['last_name'],
                    "email" => $email
                ];
                echo json_encode([
                    "success" => true,
                    "message" => "Login Successful",
                    "user" => $user
                ], JSON_UNESCAPED_SLASHES);
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

    public function logout()
    {
        if (isset($_COOKIE['token'])) {
            setcookie("token", "", time() - 3600, "/");
            echo json_encode([
                "success" => true,
                "message" => "Logged out successfully"
            ]);
        } else {
            echo json_encode([
                "success" => false,
                "message" => "Token not found"
            ]);
        }
    }


    public function updatepassword($prevpassword, $newpassword)
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = userController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("SELECT password FROM users WHERE user_id=?");
                $stmt->bind_param("s", $userId);
                $stmt->execute();
                $data = $stmt->get_result()->fetch_array(MYSQLI_ASSOC);
                $hashed_password = $data['password'];
                if (password_verify($prevpassword, $hashed_password)) {
                    $newhashed_password = password_hash($newpassword, PASSWORD_BCRYPT);
                    $stmt = $this->conn->prepare("UPDATE users SET password=? WHERE user_id=?");
                    $stmt->bind_param("ss", $newhashed_password, $userId);
                    $stmt->execute();
                    echo json_encode([
                        "success" => true,
                        "message" => "Password Updated Successfully"
                    ]);
                } else {
                    echo json_encode([
                        "success" => false,
                        "message" => "Invalid Password"
                    ]);
                }
            }
        } else {
            echo json_encode([
                "success" => false,
                "message" => "Token not found"
            ]);
        }
    }


    public function updateprofile($data)
    {

        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = userController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                if (isset($data['first_name']) && isset($data['last_name'])) {
                    $first_name = $data['first_name'];
                    $last_name = $data['last_name'];
                    $stmt = $this->conn->prepare("UPDATE users SET first_name=? , last_name=? WHERE user_id=?");
                    $stmt->bind_param("sss", $first_name, $last_name, $userId);
                    $stmt->execute();
                    echo json_encode([
                        "success" => true,
                        "message" => "Name Updated Successfully"
                    ]);
                } else if (isset($data['first_name'])) {
                    $first_name = $data['first_name'];
                    $stmt = $this->conn->prepare("UPDATE users SET first_name=? WHERE user_id=?");
                    $stmt->bind_param("ss", $first_name, $userId);
                    $stmt->execute();
                    echo json_encode([
                        "success" => true,
                        "message" => "First Name Updated Successfully"
                    ]);
                } else if (isset($data['last_name'])) {
                    $last_name = $data['last_name'];
                    $stmt = $this->conn->prepare("UPDATE users SET last_name=? WHERE user_id=?");
                    $stmt->bind_param("ss", $last_name, $userId);
                    $stmt->execute();
                    echo json_encode([
                        "success" => true,
                        "message" => "Last Name Updated Successfully"
                    ]);
                } else {
                    echo json_encode([
                        "success" => false,
                        "message" => "No change"
                    ]);
                }
            } else {
                echo json_encode([
                    "success" => false,
                    "message" => "Token Error"
                ]);
            }
        }
    }



    public function getmyprofile()
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = userController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("SELECT user_id, first_name, last_name, email FROM users Where user_id=?");
                $stmt->bind_param("s", $userId);
                $stmt->execute();
                $data = $stmt->get_result()->fetch_array(MYSQLI_ASSOC);
                if ($data) {
                    echo json_encode([
                        "success" => true,
                        "user" => $data
                    ]);
                } else {
                    echo json_encode([
                        "success" => false,
                        "message" => "User not found"
                    ]);
                }
            }
        } else {
            echo json_encode([
                "success" => false,
                "message" => "Token not found"
            ]);
        }
    }

    public function getnearestbusstand()
    {
        function getNearestBusStand($location, $radius, $apiKey)
        {
            $baseUrl = "https://maps.googleapis.com/maps/api/place/nearbysearch/json";
            // $url = "$baseUrl?location=$location&radius=$radius&type=transit_station&key=$apiKey";
            $url = "$baseUrl?location=$location&radius=$radius&type=restaurant&key=$apiKey";

            $response = file_get_contents($url);
            return json_decode($response, true);
        }

        // Example usage
        $location = "31.230463,75.778597"; // Latitude,Longitude of the property
        $radius = 5000; // Radius in meters
        $apiKey = "AIzaSyBdPDiqHlsiyUGU9jTvCTMaRx08Pl0fKMw";

        $result = getNearestBusStand($location, $radius, $apiKey);
        header('Content-Type: application/json');
        echo json_encode($result);
    }
}
