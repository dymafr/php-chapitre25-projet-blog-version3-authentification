<?php
require_once __DIR__ . '/database.php';
class AuthDB
{

    public function __construct(private PDO $pdo)
    {
    }

    function login(string $userId): void
    {
        $statement = $this->pdo->prepare('INSERT INTO session VALUES (
            :sessionid,
            :userid
        )');
        $sessionId = bin2hex(random_bytes(32));
        $statement->bindValue(':userid', $userId);
        $statement->bindValue(':sessionid', $sessionId);
        $statement->execute();
        $signature = hash_hmac('sha256', $sessionId, '4cd30a3e9bd36ae867730f712e15b4d29d0473916d5d61e8425346f277c63cf9');
        setcookie('session', $sessionId, time() + 60 * 60 * 24 * 14, '', '', false, true);
        setcookie('signature', $signature, time() + 60 * 60 * 24 * 14, "", "", false, true);
        return;
    }

    function register(array $user): void
    {
        $statement = $this->pdo->prepare('INSERT INTO user VALUES (
            DEFAULT,
            :firstname,
            :lastname,
            :email,
            :password
        )');
        $hashedPassword = password_hash($user['password'], PASSWORD_ARGON2I);
        $statement->bindValue(':firstname', $user['firstname']);
        $statement->bindValue(':lastname', $user['lastname']);
        $statement->bindValue(':email', $user['email']);
        $statement->bindValue(':password', $hashedPassword);
        $statement->execute();
        return;
    }

    function isLoggedin(): array | false
    {
        $sessionId = $_COOKIE['session'] ?? '';
        $signature = $_COOKIE['signature'] ?? '';
        if ($sessionId && $signature) {
            $hash = hash_hmac('sha256', $sessionId, '4cd30a3e9bd36ae867730f712e15b4d29d0473916d5d61e8425346f277c63cf9');
            if (hash_equals($hash, $signature)) {
                $statement = $this->pdo->prepare('SELECT * FROM session JOIN user on user.id=session.userid WHERE session.id=:sessionid');
                $statement->bindValue(':sessionid', $sessionId);
                $statement->execute();
                $user = $statement->fetch();
            }
        }
        return $user ?? false;
    }

    function logout(string $sessionId): void
    {
        $statement = $this->pdo->prepare('DELETE FROM session WHERE id=:id');
        $statement->bindValue(':id', $sessionId);
        $statement->execute();
        setcookie('session', '', time() - 1);
        setcookie('signature', '', time() - 1);
        return;
    }

    function getUserFromEmail(string $email): array | false
    {
        $statement = $this->pdo->prepare('SELECT * FROM user WHERE email=:email');
        $statement->bindValue(':email', $email);
        $statement->execute();
        return $statement->fetch();
    }
}

return new AuthDB($pdo);
