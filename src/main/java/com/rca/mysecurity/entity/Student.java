package com.rca.mysecurity.entity;
import lombok.AllArgsConstructor;
import lombok.Data;

import javax.persistence.*;
import java.util.List;


@Entity
@Data
@AllArgsConstructor
public class Student {
    @Id
    @GeneratedValue
    private int id;
    @Column(nullable = false, length = 100)
    private String firstName;
    @Column(nullable = false, length = 100)
    private String lastName;
    @Column(nullable = false, unique = true, length = 100)
    private String email;
    @ManyToOne(fetch = FetchType.EAGER,cascade = CascadeType.ALL)
    @JoinColumn(name = "user_id", nullable = false)
    private UserData created;
    @OneToMany(mappedBy = "student", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private List<Laptop> laptops;
    public Student() {
    }

    public Student(String firstName, String lastName, String email) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;

    }
}
