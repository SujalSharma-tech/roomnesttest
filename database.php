<?php

class Database
{
    private $host = "ec2-13-202-214-195.ap-south-1.compute.amazonaws.com";
    private $db_name = "users";
    private $username = "sujal";
    private $password = "#2004Sujal#";
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
