<?php
/*
 *  Copyright (C) 2015-2016  Leonardosc
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  21/01/2015
 */

class AuthMe 
{

    /** 
        * Tipos de hash que o authme suporta
    */
    const MD5 = 'md5';
    const SHA256 = 'sha256';
    const SHA1 = 'sha1';
    const WHIRLPOOL = 'whirlpool';
    const MD5VB = 'md5vb';
    const PLAINTEXT = 'plaintext';

    private $connection, $authme_table, $algorithm;

    /**
        * Construtor responsavel por criar a conexão com o banco de dados
        * @param string $db_host Host onde o MySQL se encontra
        * @param string $db_user Usuário do MySQL
        * @param string $db_pass Senha do MySQL
        * @param string $authme_table Nome da tabela onde o authme está instalado
        * @param string $algo Algoritmo usado no authme, por padrão o configurado é o SHA256
    */
    public function __construct($db_host, $db_user, $db_pass, $db_name, $authme_table, $algo = 'SHA256') 
    {

        $this->authme_table = $this->filter($authme_table);
        $this->algorithm = $algo;
        
        try {

            $this->connection = new PDO('mysql:host='.$db_host.';dbname='.$db_name.';charset=utf8;', $db_user, $db_pass);

        } catch(PDOException $e) {

            die('Ocorreu um erro ao criar a conexão com o banco de dados: '.$e->getMessage());

        }


    }

    /**
        * Destroi a instancia da classe
    */
    public function __destruct() 
    {

        $this->connection = null;
        unset($this->algorithm);
        unset($this->authme_table);
        
    }

    /**
        * Verifica se o usuário e a senha estão corretos
        * @param string $user Nome do jogador
        * @param string $pass Senha do jogador
        * @return boolean true|false true em caso de sucesso
    */
    public function authenticate($user, $pass) 
    {

        $stmt = $this->connection->prepare("SELECT password FROM {$this->authme_table} WHERE username = ?");
        $stmt->execute([$this->filter[$user]]);

        if($stmt->rowCount() > 0) {

            $data = $stmt->fetch();

            $hash_pass = $data['password'];
            return self::compare($pass, $hash_pass);

        }

        return false;

    }

    /**
        * Registra um novo jogador
        * @param string $user Nick do jogador
        * @param string $pass Senha do jogador
        * @param string $email Email do jogador
        * @param string $ip IP do jogador, por padrão definido como '0.0.0.0'
        * @return boolean true|false verdadeiro caso o registro seja bem sucedido, false caso o email já esteja registrado
    */
    public function register($user, $pass, $email = 'your@email.com', $ip = '0.0.0.0') 
    {

        $user = $this->filter($user);
        $pass = $this->filter(self::AMHash($pass));
        $email = $this->filter($email);

        if(self::isUsernameRegistered($user)) return false;

        $stmt = $this->connection->prepare("INSERT INTO {$this->authme_table} (username, password, ip, lastlogin, x, y, z, email) VALUES(?, ?, ?, 0, 0, 0, 0, ?)");

        $stmt->execute([
            $user,
            $pass,
            $ip,
            $email
        ]);

        return true;
        
    }

    /**
        * Altera a senha do jogador
        * @param string $username Usuário do jogador
        * @param string $newpass Nova senha do jogador
        * @return boolean true|false falso caso o jogador não exista e true caso não haja problema na alteração de senha
    */
    public function changePassword($username, $newpass) 
    {

        if (!self::isUsernameRegistered($username)) return false;

        $username = $this->filter($username);
        $newpass = $this->filter(self::AMHash($newpass));

        $stmt = $this->connection->prepare("UPDATE {$this->authme_table} SET password = ? WHERE username = ?");
        $stmt->execute([$newpass, $username]);
        
        return true;

    }

    /**
        * Verifica se um endereço IP já está registrado
        * @param string $ip IP
        * @return boolean true|false verdadeiro caso o IP já exista e falso caso não exista
    */
    public function isIpRegistered($ip) 
    {

        $ip  = $this->filter($ip);
        $stmt = $this->connection->prepare("SELECT ip FROM {$this->authme_table} WHERE ip = ?");
        $stmt->execute([$ip]);

        return ($stmt->rowCount() > 0) ? true : false;

    }

    /**
        * Verifica se o email já existe
        * @param string $email Email a ser verificado
        * @return boolean true|false verdadeiro caso email já exista
    */
    public function isEmailRegistered($email) 
    {

        $email = $this->filter($email);

        $stmt = $this->connection->prepare("SELECT email FROM {$this->authme_table} WHERE email = ?");
        $stmt->execute([$email]);

        return ($stmt->rowCount() > 0) ? true : false;

    }

    /**
        * Verifica se o usuário já está registrado
        * @param string $user Usuario a ser verificado
        * @return boolean true|false verdadeiro caso email já exista
    */
    public function isUsernameRegistered($user) 
    {

        $user = $this->filter($user);

        $stmt = $this->connection->prepare("SELECT username FROM {$this->authme_table} WHERE username = ?");
        $stmt->execute([$user]);

        return ($stmt->rowCount() > 0) ? true : false;

    }

    /**
        * Compara as senhas
        * @param string $pass Senha inserida pelo usuário
        * @param string $hash_pass Hash vinda do banco de dados 
        * @access private  
        * @return boolean true|false Verdadeiro caso a senha senha valida, falso se for invalida
    */
    private function compare($pass, $hash_pass) 
    {

        switch ($this->algorithm) {

            case self::SHA256:
            $shainfo = explode('$', $hash_pass);
            $pass = hash('sha256', $pass) . $shainfo[2];
            return strcasecmp($shainfo[3], hash('sha256', $pass)) == 0;

            case self::SHA1:
            return strcasecmp($hash_pass, hash('sha1', $pass)) == 0;

            case self::MD5:
            return strcasecmp($hash_pass, hash('md5', $pass)) == 0;

            case self::WHIRLPOOL:
            return strcasecmp($hash_pass, hash('whirlpool', $pass)) == 0;

            case self::MD5VB:
            $shainfo = explode('$', $hash_pass);
            $pass = hash('md5', $pass) . $shainfo[2];
            return strcasecmp($shainfo[3], hash('md5', $pass)) == 0;

            case self::PLAINTEXT:
            return $hash_pass == $pass;

            default:
            return false;

        }

    }

    /**
        * Gera a hash da senha
        * @param string $pass Senha inserida pelo usuário
        * @access private  
        * @return string|null String contendo a hash ou null em caso de erro
    */
    private function AMHash($pass) 
    {

        switch ($this->algorithm) {

            case self::SHA256:
            $salt = self::createSalt();
            return "\$SHA\$".$salt."\$" . hash('sha256', hash('sha256', $pass) . $salt);

            case self::SHA1:
            return hash('sha1', $pass);

            case self::MD5:
            return hash('md5', $pass);

            case self::WHIRLPOOL:
            return hash('whirlpool', $pass);

            case self::MD5VB:
            $salt = self::createSalt();
            return "\$MD5vb\$" . $salt . "\$" . hash('md5', hash('md5', $pass) . $salt);

            case self::PLAINTEXT:
            return $pass;

            default:
            return null;

        }

    }

    /**
        * Cria um salt aleatório
        * @access private
        * @return string Salt
    */
    private function createSalt() 
    {

        $salt = '';

        for ($i = 0; $i < 20; $i++) {
            $salt .= rand(0, 9);
        }

        return substr(hash('sha1', $salt), 0, 16);

    }

    /**
        * Trata o valor para prevenção de SQL-I
        * @param string $value Valor a ser filtrado
        * @access private
        * @return string Valor filtrado
    */
    private function filter($value)
    {

        $value = htmlspecialchars($value);
        $value = addslashes($value);

        return $value;

    }

}
