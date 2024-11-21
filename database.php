<?php

class Database
{
    // private $host = "baoujjgsjzuqlvv6pv3a-mysql.services.clever-cloud.com";
    // private $db_name = "baoujjgsjzuqlvv6pv3a";
    // private $username = "ukmwxvkswbgi855r";
    // private $password = "E8AEDEOIVkTIQ8jhuJxf";
    // private $host = "13.202.214.195";
    // private $db_name = "users";
    // private $username = "sujal";
    // private $password = "#2004Sujal#";
    // private $host = "databaseroomnest.c3u4826aedy4.ap-south-1.rds.amazonaws.com";
    // private $db_name = "roomnest";
    // private $username = "admin";
    // private $password = "#2004Sujal#";
    private $host = "localhost";
    private $db_name = "roomnest";
    private $username = "root";
    private $password = "";

    private $conn;
    public function getConnection()
    {
        $this->conn = null;
        try {
            $this->conn = new mysqli($this->host, $this->username, $this->password, $this->db_name);
        } catch (mysqli_sql_exception $e) {
            echo "Connection error: " . $e->getMessage();
        }

        return $this->conn;
    }
}

$db = new Database();
$conn = $db->getConnection();


// function logout()
// {
//     if (isset($_COOKIE['token'])) {
//         setcookie("token", "", time() - 3600, "/");
//         echo json_encode([
//             "success" => true,
//             "message" => "Logged out successfully"
//         ]);
//     } else {
//         echo json_encode([
//             "success" => false,
//             "message" => "Token not found"
//         ]);
//     }
// }

// logout();
