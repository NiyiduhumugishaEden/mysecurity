package com.rca.mysecurity.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.rca.mysecurity.entity.Student;

@Repository
public interface IStudentRepository extends JpaRepository<Student, Integer> {
}
