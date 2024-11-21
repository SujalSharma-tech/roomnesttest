use Cloudinary\Configuration\Configuration;
use Cloudinary\Api\Upload\UploadApi;

Configuration::instance("cloudinary://557733514295329:99MOXH_LN-BRIm1jKNilwr-_ds0@dxnb4inln?secure=true'");
$upload = new UploadApi();

echo json_encode(
$upload->upload('C:\xampp\htdocs\RoomNestServer\imagesample.png', [
'use_filename' => true,

]),
);