<?php

class Database
{
    private $host = "roomnest.c9so22qkqtef.eu-north-1.rds.amazonaws.com";
    private $db_name = "roomnest";
    private $username = "admin";
    private $password = "#78697265Sujal#";
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
