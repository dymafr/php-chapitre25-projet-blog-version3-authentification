<?php
require_once __DIR__ . '/../database.php';

class ArticleDB
{
    function __construct(private PDO $pdo)
    {
    }
    public function fetchAll(): array
    {
        $statement = $this->pdo->prepare('SELECT article.*, user.firstname, user.lastname FROM article LEFT JOIN user ON article.author = user.id');
        $statement->execute();
        return $statement->fetchAll();
    }

    public function fetchOne(string $id): array
    {
        $statement = $this->pdo->prepare('SELECT article.*, user.firstname, user.lastname FROM article LEFT JOIN user ON article.author = user.id WHERE article.id=:id');
        $statement->bindValue(':id', $id);
        $statement->execute();
        return $statement->fetch();
    }

    public function deleteOne(string $id): string
    {
        $statement = $this->pdo->prepare('DELETE FROM article WHERE id=:id');
        $statement->bindValue(':id', $id);
        $statement->execute();
        return $id;
    }

    public function createOne($article): array
    {
        $statement = $this->pdo->prepare('
            INSERT INTO article (
                title,
                category,
                content,
                image,
                author
            ) VALUES (
                :title,
                :category,
                :content,
                :image,
                :author
            )
        ');
        $statement->bindValue(':title', $article['title']);
        $statement->bindValue(':content', $article['content']);
        $statement->bindValue(':category', $article['category']);
        $statement->bindValue(':image', $article['image']);
        $statement->bindValue(':author', $article['author']);
        $statement->execute();
        return $this->fetchOne($this->pdo->lastInsertId());
    }

    public function updateOne($article): array
    {
        $statement = $this->pdo->prepare('
            UPDATE article
            SET
                title=:title,
                category=:category,
                content=:content,
                image=:image,
                author=:author
            WHERE id=:id
        ');
        $statement->bindValue(':title', $article['title']);
        $statement->bindValue(':content', $article['content']);
        $statement->bindValue(':category', $article['category']);
        $statement->bindValue(':image', $article['image']);
        $statement->bindValue(':id', $article['id']);
        $statement->bindValue(':author', $article['author']);
        $statement->execute();
        return $article;
    }

    public function fetchUserArticle(string $authorId): array
    {
        $statement = $this->pdo->prepare('SELECT * FROM article WHERE author=:authorId');
        $statement->bindValue(':authorId', $authorId);
        $statement->execute();
        return $statement->fetchAll();
    }
}


return new ArticleDB($pdo);
