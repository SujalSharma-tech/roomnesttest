<?php
require_once('./database.php');

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\JWTExceptionWithPayloadInterface;

header('Content-Type: application/json');

class ListingController
{
    private $conn;
    public function __construct($conn)
    {
        // $db = new Database();
        // $this->conn = $db->getConnection();
        $this->conn = $conn;
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

    public function createlisting($title, $desc, $no_of_rooms, $rent, $address, $city, $state, $postal, $wifi)
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("INSERT INTO listings (title,description,no_of_rooms,rent,address,city,state,postal_code,wifi,user_id) VALUES(?,?,?,?,?,?,?,?,?,?)");
                $stmt->bind_param("ssidssssis",$title, $desc, $no_of_rooms, $rent, $address, $city, $state, $postal, $wifi, $userId);
                if ($stmt->execute()) {
                    echo json_encode([
                        "success" => true,
                        "message" => "Listing Created Successfully"
                    ]);
                } else {
                    echo json_encode([
                        "success" => false,
                        "message" => "Failed to create listing"
                    ]);
                }
            }
        }
    }

    public function fetchlistings()
    {
        $stmt = $this->conn->prepare("SELECT * FROM listings");
        $stmt->execute();
        $result = $stmt->get_result();
        $listings = [];
        while ($row = $result->fetch_assoc()) {
            array_push($listings, $row);
        }
        echo json_encode($listings);
    }
}
