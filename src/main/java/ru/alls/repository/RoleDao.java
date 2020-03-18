package ru.alls.repository;


import org.springframework.stereotype.Repository;
import ru.alls.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;



@Repository
public interface RoleDao extends JpaRepository<Role, Long> {
}
