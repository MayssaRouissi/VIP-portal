package fr.insalyon.creatis.vip.core.server.business;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import fr.insalyon.creatis.devtools.MD5;
import fr.insalyon.creatis.vip.core.client.VipException;
import fr.insalyon.creatis.vip.core.models.User;
import fr.insalyon.creatis.vip.core.server.business.base.CommonBusiness;
import fr.insalyon.creatis.vip.core.server.dao.DAOException;
import fr.insalyon.creatis.vip.core.server.dao.UserDAO;

@Service
public class PasswordBusiness extends CommonBusiness {

    private final UserDAO userDAO;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @Autowired
    public PasswordBusiness(UserDAO userDAO) {
        this.userDAO = userDAO;
    }
    public boolean isModernFormat(String storedHash) {
        return storedHash != null
                && (storedHash.startsWith("$2a$")
                || storedHash.startsWith("$2b$")
                || storedHash.startsWith("$2y$"));
    }

    public String hash(String plainPassword) {
        return encoder.encode(plainPassword);
    }

    public boolean verify(String plainPassword, String storedHash) {
        return encoder.matches(plainPassword, storedHash);
    }

    public void update(User user, String currentPassword, String newPassword) throws VipException {
        try {
            String storedHash = userDAO.getPasswordHash(user.getEmail());
            boolean currentPasswordCorrect;

            if (storedHash != null && isModernFormat(storedHash)) {
                currentPasswordCorrect = verify(currentPassword, storedHash);
            } else {
                String md5Attempt = MD5.get(currentPassword);
                currentPasswordCorrect = storedHash != null && md5Attempt.equals(storedHash);
            }

            if (!currentPasswordCorrect) {
                logger.error("Wrong current password for {}", user.getEmail());
                throw new VipException("The current password mismatch.");
            }

            String newPasswordHash = hash(newPassword);
            userDAO.resetPassword(user.getEmail(), newPasswordHash);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            logger.error("Error updating password for {}", user.getEmail(), ex);
            throw new VipException(ex);
        } catch (DAOException ex) 
            {throw new VipException(ex);}
    }

    public void setPassword(String email, String newPassword) throws VipException {
        try {
            userDAO.resetPassword(email, hash(newPassword));
        } catch (DAOException ex) {
            logger.error("Error setting password for {}", email, ex);
            throw new VipException(ex);
        }
    }

    public void reset(String email, String code, String password) throws VipException {
        try {
            User user = userDAO.get(email);

            if (code.equals(user.getCode())) {
                userDAO.resetPassword(email, hash(password));
            } else {
                logger.error("Wrong reset code for {} : {}", email, code);
                throw new VipException("Wrong reset code.");
            }
        } catch (DAOException ex) {
            logger.error("Error resetting password for {}", email, ex);
            throw new VipException(ex);
        }
    }
}