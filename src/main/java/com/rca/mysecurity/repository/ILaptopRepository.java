package com.rca.mysecurity.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.rca.mysecurity.entity.Laptop;


@Repository
public interface ILaptopRepository extends JpaRepository<Laptop, Integer> {
}
