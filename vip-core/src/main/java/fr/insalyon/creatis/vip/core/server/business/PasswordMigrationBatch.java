package fr.insalyon.creatis.vip.core.server.business;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import fr.insalyon.creatis.vip.core.server.dao.DAOException;
import fr.insalyon.creatis.vip.core.server.dao.UserDAO;


@Service
public class PasswordMigrationBatch {

    private static final Logger logger = LoggerFactory.getLogger(PasswordMigrationBatch.class);
    private static final int BATCH_SIZE = 200;

    private final UserDAO userDAO;
    private final PasswordBusiness passwordBusiness;

    @Autowired
    public PasswordMigrationBatch(UserDAO userDAO, PasswordBusiness passwordBusiness) {
        this.userDAO = userDAO;
        this.passwordBusiness = passwordBusiness;
    }


    @EventListener(ContextRefreshedEvent.class)
    public void onStartup(ContextRefreshedEvent event) {
        if (event.getApplicationContext().getParent() != null) {
            return; 
        }
        logger.info("Application context ready:running password migration check on startup");
        runOnce();
    }

    @Scheduled(cron = "0 0 5 * * *")
    public void scheduledCheck() {
        logger.info("scheduled password migration check triggered");
        runOnce();
    }

    public void runOnce() {
        logger.info("=starting MD5 ->double-hash migration=");

        int totalMigrated = 0;
        int offset = 0;

        Set<String> failedEmails = new HashSet<>();

        while (true) {
            List<String> fetched;
            try {
                fetched = userDAO.getEmailsWithLegacyPassword(offset, BATCH_SIZE);
            } catch (DAOException e) {
                logger.error("Error fetching batch of legacy accounts at offset {}", offset, e);
                break;
            }

            if (fetched.isEmpty()) {
                break;
            }

            List<String> emailsToProcess = fetched.stream()
                    .filter(email -> !failedEmails.contains(email))
                    .toList();

            if (emailsToProcess.isEmpty()) {

                logger.warn("No progress possible: {} account(s) remain stuck in failure, stopping. "
                        + "Failed accounts: {}", failedEmails.size(), failedEmails);
                break;
            }

            int migratedInBatch = 0;
            for (String email : emailsToProcess) {
                if (migrateOne(email)) {
                    totalMigrated++;
                    migratedInBatch++;
                } else {
                    failedEmails.add(email);
                }
            }

            logger.info("Batch processed: {} accounts so far ({} failed so far)",
                    totalMigrated, failedEmails.size());

            if (migratedInBatch == 0) {
                logger.warn("No account migrated in this pass, stopping to avoid infinite loop.");
                break;
            }

        }

        if (!failedEmails.isEmpty()) {
            logger.error("Migration batch finished WITH {} failed account(s), please investigate: {}",
                    failedEmails.size(), failedEmails);
        }
        logger.info("=== Migration batch finished. Total accounts migrated: {} ===", totalMigrated);
    }

    private boolean migrateOne(String email) {
        try {
            String currentMd5Hash = userDAO.getPasswordHash(email);
            if (currentMd5Hash == null) {
                return false;
            }

            String doubleHash = passwordBusiness.hash(currentMd5Hash);
            userDAO.markDoubleHashed(email, doubleHash);
            return true;

        } catch (DAOException e) {
            logger.error("Error migrating password for {}", email, e);
            return false;
        }
    }
}