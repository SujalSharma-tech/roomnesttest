<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require_once('./user-controller.php');
require_once('./listing-controller.php');
require_once('./database.php');
header('Content-Type: application/json');

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
        } else if (preg_match('/\/api\/v1\/listing\/getlistings/', $uri)) {
            $listing_controller->fetchlistings();
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
        } else if (preg_match('/\/api\/v1\/listing\/createlisting/', $uri)) {
            $data = json_decode(file_get_contents("php://input"), true);
            $listing_controller->createlisting($data['title'], $data['description'], $data['no_of_rooms'], $data['rent'], $data['address'], $data['city'], $data['state'], $data['postal'], $data['wifi']);
        } else {
            echo json_encode(['error' => 'Invalid request']);
        }
        break;

    default:
        echo json_encode(['error' => 'Invalid request']);
        break;
}
