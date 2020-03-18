package ru.alls.userservices;
import ru.alls.entities.UserDataSet;

import java.util.List;

public interface UserService {

	public List<UserDataSet> getAllUsers();
	public UserDataSet getUserById(Long id);
	public boolean saveUser(UserDataSet user);
	public boolean deleteUserById(Long id);

}