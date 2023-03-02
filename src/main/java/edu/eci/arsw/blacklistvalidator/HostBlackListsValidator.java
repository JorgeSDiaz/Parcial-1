/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT = 5;
    HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();

    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     *
     * @param ipaddress suspicious host's IP address.
     * @return Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int cantThreads) {
        LinkedList<Integer> blackListOcurrences=new LinkedList<>();
        List<HBLVThread> hblvThreads = new ArrayList<>();
        List<Integer> ranges = ranges(cantThreads);
        for (int i = 0; i < cantThreads; i++) {
            HBLVThread thread;
            if (i == 0) {
                thread = new HBLVThread(ipaddress, 0, ranges.get(i));
            } else {
                thread = new HBLVThread(ipaddress, ranges.get(i - 1) + 1, ranges.get(i));
            }
            System.out.println("Creando: " + thread.getName());
            hblvThreads.add(thread);
        }
        for (HBLVThread hblvThread : hblvThreads) {
            System.out.println("Corriendo: " + hblvThread.getName());
            hblvThread.run();
        }

        for (HBLVThread hblvThread: hblvThreads) {
            System.out.println("Esperando" + hblvThread.getName());
            try {
                hblvThread.join();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        for (HBLVThread hblvThread: hblvThreads) {
            System.out.println("Acumulando" + hblvThread.getName());
            blackListOcurrences.addAll(hblvThread.blackListOcurrences);
        }

        return blackListOcurrences;
    }

    private List<Integer> ranges(int cantThreads) {
        List<Integer> ranges = new ArrayList<>();
        int sep = skds.getRegisteredServersCount() / cantThreads;
        int res = skds.getRegisteredServersCount();
        for (int i = 0; i < cantThreads; i++) {
            if (res > sep && i != cantThreads - 1) {
                ranges.add(sep);
                res -= sep;
            } else {
                ranges.add(res);
            }
        }
        return ranges;
    }
}
