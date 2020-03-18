package ru.alls.userservices;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.alls.entities.Role;
import ru.alls.entities.UserDataSet;
import ru.alls.repository.UserRepository;


import java.util.HashSet;
import java.util.Set;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        UserDataSet user = userRepository.findByLogin(login);
//        System.out.println(user.getLogin() + " OUR LOGIN!!");
//        if(user == null){
//            throw new UsernameNotFoundException("User not authorized.");
//        }

        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        System.out.println("rabotaet");

        for (Role role : user.getRoles()) {
            grantedAuthorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return new org.springframework.security.core.userdetails.User(user.getLogin(), user.getPassword(), grantedAuthorities);
    }
}
