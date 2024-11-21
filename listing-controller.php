<?php
require_once('./database.php');
require_once('./vendor/autoload.php');

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\JWTExceptionWithPayloadInterface;
use Cloudinary\Configuration\Configuration;
use Cloudinary\Api\Upload\UploadApi;



header('Content-Type: application/json');

// Configuration::instance('cloudinary://557733514295329:99MOXH_LN-BRIm1jKNilwr-_ds0@dxnb4inln?secure=true');

Configuration::instance('cloudinary://494122998623646:RdFkop-yUGAWK506icEjvHLPVH0@dxnb4inln?secure=true');

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
            echo json_encode(["success" => false, "message" => "Token Expired or Invalid"]);
        }
    }

    public function createlisting($title, $desc, $no_of_rooms, $rent, $address, $city, $state, $postal, $wifi, $pets_allowed)
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("INSERT INTO listings (title,description,no_of_rooms,rent,address,city,state,postal_code,wifi,user_id,pets_allowed) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
                $stmt->bind_param("ssidssssisi", $title, $desc, $no_of_rooms, $rent, $address, $city, $state, $postal, $wifi, $userId, $pets_allowed);
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

    public function deletelisting($id)
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;

                $stmt = $this->conn->prepare("DELETE FROM listings WHERE id=? AND user_id=?");
                $stmt->bind_param("is", $id, $userId);
                if ($stmt->execute()) {
                    echo json_encode([
                        "success" => true,
                        "message" => "Listing Deleted Successfully"
                    ]);
                } else {
                    echo json_encode([
                        "success" => false,
                        "message" => "Failed to delete listing"
                    ]);
                }
            }
        }
    }


    public function fetchuserlistings()
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("SELECT * FROM listings WHERE user_id=?");
                $stmt->bind_param("s", $userId);
                $stmt->execute();
                $result = $stmt->get_result();
                $listings = [];
                while ($row = $result->fetch_assoc()) {
                    array_push($listings, $row);
                }
                echo json_encode($listings);
            }
        }
    }

    public function changeStatus($id, $status)
    {
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("UPDATE listings SET is_active=? WHERE id=? AND user_id=?");
                $stmt->bind_param("iis", $status, $id, $userId);
                if ($stmt->execute()) {
                    echo json_encode([
                        "success" => true,
                        "message" => "Listing Status Changed Successfully"
                    ]);
                }
            }
        }
    }


    public function fetchlistings()
    {
        $stmt = $this->conn->prepare("SELECT * FROM listings WHERE is_active=?");
        $val = 1;
        $stmt->bind_param("i", $val);
        $stmt->execute();
        $result = $stmt->get_result();
        $listings = [];
        while ($row = $result->fetch_assoc()) {
            array_push($listings, $row);
        }
        echo json_encode($listings);
    }

    public function locallisting($data, $images)
    {

        $upload = new UploadApi();
        $imageUrls = [];
        if (isset($_FILES['images'])) {
            foreach ($_FILES['images']['tmp_name'] as $key => $tmpName) {
                if (!empty($tmpName)) {
                    $uploadResult = $upload->upload($tmpName, [
                        'folder' => 'listings/',
                    ]);
                    $imageUrls[] = $uploadResult['secure_url'];
                }
            }
        }




        $title = $_POST['title'];
        $desc = $_POST['description'];
        $no_of_rooms = $_POST['bedrooms'];
        $rent = $_POST['price'];
        $address = $_POST['address'];
        $city = $_POST['city'];
        $state = "Punjab";
        $postal = 144401;
        $wifi = filter_var($_POST['wifiAvailable'], FILTER_VALIDATE_BOOLEAN);
        $pets_allowed = filter_var($_POST['petAllowed'], FILTER_VALIDATE_BOOLEAN);
        $latitude = floatval($_POST['latitude']);
        $longitude = floatval($_POST['longitude']);
        $furished = filter_var($_POST['furnished'], FILTER_VALIDATE_BOOLEAN);
        $utilities_included = filter_var($_POST['utilitiesAvailable'], FILTER_VALIDATE_BOOLEAN);
        $parking = filter_var($_POST['parking'], FILTER_VALIDATE_BOOLEAN);
        $additional_photos = json_encode($imageUrls, JSON_UNESCAPED_SLASHES);
        $laundry = filter_var($_POST['laundryAvailable'], FILTER_VALIDATE_BOOLEAN);
        // echo json_encode([

        //     "state" => $state,
        //     "postal" => $postal,
        //     "wifi" => $wifi,
        //     "pets_allowed" => $pets_allowed,
        //     "latitude" => $latitude,
        //     "longitude" => $longitude,
        //     "furished" => $furished,
        //     "utilities_included" => $utilities_included,
        //     "parking" => $parking,
        //     "laundry" => $laundry
        // ]);
        // die();


        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            // echo $decoded;
            if ($decoded) {
                $userId = $decoded->id;
                $stmt = $this->conn->prepare("INSERT INTO listings (title,description,no_of_rooms,rent,address,city,state,postal_code,wifi,pets_allowed,latitude,longitude,furnished,utilities_included,parking,additional_photos,laundry,user_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
                $stmt->bind_param("ssidssssiiddiiisis", $title, $desc, $no_of_rooms, $rent, $address, $city, $state, $postal, $wifi, $pets_allowed, $latitude, $longitude, $furished, $utilities_included, $parking, $additional_photos, $laundry, $userId);
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


    public function filterlisting()
    {
        $input = json_decode(file_get_contents('php://input'), true);

        // Extract the filter values
        $location = $input['location'] ?? '';
        $propertyType = $input['propertyType'] ?? 'any';
        $bedrooms = $input['bedrooms'] ?? '';
        $minPrice = $input['minPrice'] ?? '';
        $maxPrice = $input['maxPrice'] ?? '';

        // Base SQL query
        $sql = "SELECT * FROM listings WHERE is_active=1";
        $params = [];
        $types = '';
        if (!empty($location)) {
            $sql .= " AND (city LIKE ?";
            $params[] = "%$location%";
            $types .= 's';
            $sql .= " OR title LIKE ?";
            $params[] = "%$location%";
            $types .= 's';
            $sql .= " OR address LIKE ?";
            $params[] = "%$location%";
            $types .= 's';
            $sql .= " OR description LIKE ?";
            $params[] = "%$location%";
            $types .= 's';
            $sql .= " OR state LIKE ?)";
            $params[] = "%$location%";
            $types .= 's';
        }
        if ($propertyType !== 'any') {
            $sql .= " AND property_type = ?";
            $params[] = $propertyType;
            $types .= 's';
        }
        if (!empty($bedrooms)) {
            $sql .= " AND no_of_rooms = ?";
            $params[] = (int)$bedrooms;
            $types .= 'i';
        }
        if (!empty($minPrice)) {
            $sql .= " AND rent >= ?";
            $params[] = (float)$minPrice;
            $types .= 'd';
        }
        if (!empty($maxPrice)) {
            $sql .= " AND rent <= ?";
            $params[] = (float)$maxPrice;
            $types .= 'd';
        }

        // echo $sql;

        // Prepare the SQL statement

        $stmt = $this->conn->prepare($sql);

        // Bind parameters if any are present
        if (!empty($params)) {
            $stmt->bind_param($types, ...$params);
        }

        // Execute the query
        $stmt->execute();
        $result = $stmt->get_result();

        // Fetch results
        $properties = [];
        while ($row = $result->fetch_assoc()) {
            $properties[] = $row;
        }

        // Return the response
        echo json_encode([
            "success" => true,
            "properties" => $properties,
        ]);
    }

    public function togglesaveproperty($property_id)
    {

        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            if ($decoded) {
                $user_id = $decoded->id;
                $checkQuery = "SELECT id FROM saved_properties WHERE user_id = ? AND property_id = ?";
                $stmt = $this->conn->prepare($checkQuery);
                $stmt->bind_param("si", $user_id, $property_id);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    // If already saved, unsave it
                    $deleteQuery = "DELETE FROM saved_properties WHERE user_id = ? AND property_id = ?";
                    $deleteStmt = $this->conn->prepare($deleteQuery);
                    $deleteStmt->bind_param("si", $user_id, $property_id);

                    if ($deleteStmt->execute()) {
                        echo json_encode(['success' => true, 'message' => 'Property unsaved.']);
                    } else {
                        echo json_encode(['success' => false, 'error' => 'Failed to unsave property.']);
                    }
                } else {
                    // If not saved, save it
                    $insertQuery = "INSERT INTO saved_properties (user_id, property_id) VALUES (?, ?)";
                    $insertStmt = $this->conn->prepare($insertQuery);
                    $insertStmt->bind_param("si", $user_id, $property_id);

                    if ($insertStmt->execute()) {
                        echo json_encode(['success' => true, 'message' => 'Property saved.']);
                    } else {
                        echo json_encode(['success' => false, 'error' => 'Failed to save property.']);
                    }
                }
            }
        }
    }

    public function fetchsavedproperties()
    {

        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            $decoded = ListingController::decodeToken($token);
            if ($decoded) {
                $user_id = $decoded->id;
                $query = "SELECT property_id FROM saved_properties WHERE user_id = ?";
                $stmt = $this->conn->prepare($query);
                $stmt->bind_param("s", $user_id);

                if ($stmt->execute()) {
                    $result = $stmt->get_result();
                    $saved_properties = [];

                    while ($row = $result->fetch_assoc()) {
                        $saved_properties[] = $row['property_id'];
                    }

                    echo json_encode(['success' => true, 'saved_properties' => $saved_properties]);
                } else {
                    echo json_encode(['success' => false, 'error' => 'Failed to fetch saved properties.']);
                }
            }
        }
    }
}
