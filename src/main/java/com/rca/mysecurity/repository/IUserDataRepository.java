package com.rca.mysecurity.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.rca.mysecurity.entity.UserData;
import java.util.Optional;


@Repository
public interface IUserDataRepository extends JpaRepository<UserData, Integer> {
    Optional<UserData> findByEmail(String email);
}


