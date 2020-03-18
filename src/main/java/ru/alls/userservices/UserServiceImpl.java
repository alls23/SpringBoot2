package ru.alls.userservices;


import ru.alls.entities.Role;
import ru.alls.entities.UserDataSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.alls.repository.RoleDao;
import ru.alls.repository.UserRepository;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UserServiceImpl implements UserService {


    // Implementing Constructor based DI

    private UserRepository repository;

    @Autowired
    private RoleDao roleDao;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Autowired
    public UserServiceImpl(UserRepository repository) {
        this.repository = repository;
    }

    public UserDataSet findUserByName(String name) {
        UserDataSet userDataSet = repository.findByName(name);
        return userDataSet;
    }

    public UserDataSet findByLogin(String login){
        UserDataSet userDataSet = repository.findByLogin(login);
        return userDataSet;
    }

    @Override
    public List<UserDataSet> getAllUsers() {
        List<UserDataSet> list = new ArrayList<>();
        repository.findAll().forEach(e -> list.add(e));
        return list;
    }

    @Override
    public UserDataSet getUserById(Long id) {
        UserDataSet userDataSet = repository.findById(id).get();
        return userDataSet;
    }

    @Override
    public boolean saveUser(UserDataSet user) {

        try {
            Set<Role> roles = new HashSet<>();
            roles.add(roleDao.getOne(1L));
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user.setRoles(roles);
            repository.save(user);
            return true;
        }catch(Exception ex) {
            return false;
        }
    }

    @Override
    public boolean deleteUserById(Long id) {
        try {
            repository.deleteById(id);
            return true;
        }catch(Exception ex) {
            return false;
        }
    }





}
