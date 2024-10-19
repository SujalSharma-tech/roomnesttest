<?php

class Database
{
    private $host = "databaseroomnest.c3u4826aedy4.ap-south-1.rds.amazonaws.com";
    private $db_name = "roomnest";
    private $username = "admin";
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
