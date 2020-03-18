package ru.alls.repository;
import org.springframework.stereotype.Repository;
import ru.alls.entities.UserDataSet;
import org.springframework.data.repository.CrudRepository;


@Repository
public interface UserRepository extends CrudRepository<UserDataSet, Long> {
    UserDataSet findByName(String name);
    UserDataSet findByLogin(String login);
	
}