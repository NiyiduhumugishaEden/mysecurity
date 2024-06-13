package com.rca.mysecurity.services;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.rca.mysecurity.entity.Student;
import com.rca.mysecurity.repository.IStudentRepository;
@Service
public class StudentService {
    @Autowired
    private IStudentRepository repo;
    public void addStudent(Student st) {
        repo.save(st);
    }
}
