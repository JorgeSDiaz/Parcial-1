package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HBLVThread extends Thread {
    LinkedList<Integer> blackListOcurrences=new LinkedList<>();
    int ocurrencesCount=0;
    HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
    int checkedListsCount=0;
    String ipaddress;
    private static final int BLACK_LIST_ALARM_COUNT=5;
    int start, end;

    public HBLVThread(String ipaddress, int start, int end) {
        this.ipaddress = ipaddress; this.start = start; this.end = end;
    }

    @Override
    public void run() {
        for (int i=start;i<end && ocurrencesCount<BLACK_LIST_ALARM_COUNT;i++){
            checkedListsCount++;

            if (skds.isInBlackListServer(i, ipaddress)){
                ocurrence(i);
            }
        }

        if (ocurrencesCount>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});

//        return blackListOcurrences;
    }

    private synchronized void ocurrence(int i) {
        System.out.printf("Entra Synchronized: " + this.getName());
        blackListOcurrences.add(i);
        ocurrencesCount++;
    }

    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
}
