package com.krakedev.jwt.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;



@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    // Inyección por constructor
    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    // Guardar usuario
    public Usuario guardar(Usuario usuario) {
    	
    	//Encriptar contraseña
    	String contrasenaEncriptada = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());
    	//Contraseña encriptada
    	usuario.setPassword(contrasenaEncriptada);

        Optional<Usuario> existente =
                usuarioRepository.findByUsername(
                        usuario.getUsername());

        if(existente.isPresent()) {
            throw new RuntimeException(
                    "El username ya existe");
        }

        return usuarioRepository.save(usuario);
    }

    // Buscar por username
    public Usuario buscarPorUsername(String username) {
        return usuarioRepository.findByUsername(username)
                .orElse(null);
    }

    // Autenticar usuario
    public boolean autenticar(String username, String password) {

        Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(username);

        if (usuarioOpt.isPresent()) {

            Usuario usuario = usuarioOpt.get();

            if (BCrypt.checkpw(password, usuario.getPassword())) {
                return true;
            }
        }

        return false;
    }
}