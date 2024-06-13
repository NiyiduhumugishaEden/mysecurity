package com.rca.mysecurity.controller;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.rca.mysecurity.entity.Student;
import com.rca.mysecurity.entity.UserData;
import com.rca.mysecurity.services.JwtService;
import com.rca.mysecurity.services.StudentService;
import com.rca.mysecurity.services.UserDataService;



@RestController
@RequestMapping("/academics")
public class StudentController {
    @Autowired
    private StudentService studentService;
    @Autowired
    private UserDataService userServices;
    @Autowired
    private JwtService jwtService;

    @PostMapping("/registration")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public void addStudent(@RequestBody Student student, HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
        if (authHeader != null && authHeader.startsWith("Bearer")) {
            token = authHeader.substring(7);
            username = jwtService.extractUsername(token);
        }
        UserData info = userServices.loadCurrentUser(username);
        student.setCreated(info);
        studentService.addStudent(student);
    }

    @GetMapping("/info")
    public String info() {
        return "Amazing day";
    }
}