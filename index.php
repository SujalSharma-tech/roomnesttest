<?php
// header('Access-Control-Allow-Origin: http://localhost:5173');
// header('Access-Control-Allow-Credentials: true');
// header('Content-Type: application/json, multipart/form-data');
// header("Access-Control-Allow-Headers: *");

header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");

header('Access-Control-Allow-Credentials: true');

require_once('./user-controller.php');
require_once('./listing-controller.php');
require_once('./database.php');

use Cloudinary\Configuration\Configuration;
use Cloudinary\Api\Upload\UploadApi;

Configuration::instance('cloudinary://494122998623646:RdFkop-yUGAWK506icEjvHLPVH0@dxnb4inln?secure=true');

// header('Content-Type: application/json, multipart/form-data');
// header('Content-Type: multipart/form-data');



require('./vendor/autoload.php');
$db = new Database();
$conn = $db->getConnection();
$method = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];
$user_controller = new UserController($conn);
$listing_controller = new ListingController($conn);
switch ($method) {
    case 'GET':

        if (preg_match('/\/api\/v1\/user\/getprofile/', $uri)) {

            $user_controller->getmyprofile();
        } else if (preg_match('/\/api\/v1\/user\/logout/', $uri)) {
            $user_controller->logout();
        } else if (preg_match('/\/api\/v1\/listing\/getlistings/', $uri)) {
            $listing_controller->fetchlistings();
        } else if (preg_match('/\/api\/v1\/listing\/getuserlistings/', $uri)) {
            $listing_controller->fetchuserlistings();
        } else if (preg_match('/\/api\/v1\/listing\/getlocation/', $uri)) {
            $user_controller->getnearestbusstand();
        } else if (preg_match('/\/api\/v1\/listing\/getsavedproperties/', $uri)) {

            $listing_controller->fetchsavedproperties();
        } else {
            echo json_encode(['error' => 'Invalid request']);
        }
        break;

    case 'POST':

        if (preg_match('/\/api\/v1\/user\/register/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $user_controller->register($data['first_name'], $data['last_name'], $data['email'], $data['password']);
        } else if (preg_match('/\/api\/v1\/user\/login/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $user_controller->login($data['email'], $data['password']);
        } else if (preg_match('/\/api\/v1\/user\/updateprofile/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $user_controller->updateprofile($data);
        } else if (preg_match('/\/api\/v1\/user\/updatepassword/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $user_controller->updatepassword($data['currpassword'], $data['newpassword']);
        } else if (preg_match('/\/api\/v1\/listing\/deletelisting/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $listing_controller->deletelisting($data['id']);
        } else if (preg_match('/\/api\/v1\/listing\/createlisting/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $listing_controller->createlisting($data['title'], $data['description'], $data['no_of_rooms'], $data['rent'], $data['address'], $data['city'], $data['state'], $data['postal_code'], $data['wifi'], $data['pets_allowed']);
        } else if (preg_match('/\/api\/v1\/listing\/local/', $uri)) {
            $data = $_POST;
            $images = $_FILES['images'];
            $listing_controller->locallisting($data, $images);
        } else if (preg_match('/\/api\/v1\/listing\/filterlisting/', $uri)) {
            $listing_controller->filterlisting();
        } else if (preg_match('/\/api\/v1\/listing\/changestatus/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $listing_controller->changestatus($data['id'], $data['status']);
        } else if (preg_match('/\/api\/v1\/listing\/togglesaveproperty/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $listing_controller->togglesaveproperty($data['property_id']);
        } else {
            echo json_encode(['error' => 'Invalid request']);
        }
        break;

    default:
        echo json_encode(['error' => 'Invalid request']);
        break;
}
