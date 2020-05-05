import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
 
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
 
 
public class LdapSimpleAuth {
 
    /** Public methods **/
     
    public static String addObjectMembership(String childObjDn, String parentObjDn, String memberAttr, String ldapUser, String ldapHost, String ldapPort, String ldapPassword) {
 
        InitialDirContext ctx = connectToLdap(ldapUser, ldapHost, ldapPort, ldapPassword);
        ModificationItem[] mods = new ModificationItem[1];
        Attribute mod0 = new BasicAttribute(memberAttr, childObjDn);
        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod0);
         
        if (ctx != null) {
            try {
                ctx.modifyAttributes(parentObjDn, mods);
                closeLdapConnection(ctx);
                return "true";
            } catch (Exception e) {
                System.out.println(e);
                closeLdapConnection(ctx);
                return "false";
            }
        }
        return "false";
    }
     
     
    public static String removeObjectMembership(String childObjDn, String parentObjDn, String memberAttr, String ldapUser, String ldapHost, String ldapPort, String ldapPassword) {
 
        InitialDirContext ctx = connectToLdap(ldapUser, ldapHost, ldapPort, ldapPassword);
        ModificationItem[] mods = new ModificationItem[1];
        Attribute mod0 = new BasicAttribute(memberAttr, childObjDn);
        mods[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, mod0);
         
        if (ctx != null) {
            try {
                ctx.modifyAttributes(parentObjDn, mods);
                closeLdapConnection(ctx);
                return "true";
            } catch (Exception e) {
                System.out.println(e);
                closeLdapConnection(ctx);
                return "false";
            }
        }
        return "false";
    }
 
    public static String checkConnection(String ldapUser, String ldapHost, String ldapPort, String ldapPassword) {
        InitialDirContext ctx = connectToLdap(ldapUser, ldapHost, ldapPort, ldapPassword);
        if ( ctx != null) {
            closeLdapConnection(ctx);
            return "true";
        } else {
            return "false";
        }
    }
 
    public static String checkObjectDnExists(String objectDn, String ldapUser, String ldapHost, String ldapPort, String ldapPassword) {
        InitialDirContext ctx = connectToLdap(ldapUser, ldapHost, ldapPort, ldapPassword);
        if (findObjectWithDn(ctx, "entrydn", objectDn) != null || findObjectWithDn(ctx, "dn", objectDn) != null || findObjectWithDn(ctx, "distinguishedname", objectDn) != null) {
            closeLdapConnection(ctx);
            return "true";
        }
        closeLdapConnection(ctx);
        return "false";
    }
 
    public static String checkAttributeExistsInObject(String attrName, String objectDn, String ldapUser, String ldapHost, String ldapPort, String ldapPassword) {
         
        InitialDirContext ctx = connectToLdap(ldapUser, ldapHost, ldapPort, ldapPassword);
        if (findObjectWithDnAndValue(ctx, attrName, "*", objectDn) != null) {
            closeLdapConnection(ctx);
            return "true";
        }
        closeLdapConnection(ctx);
        return "false";
    }
     
    public static String checkObjectXisMemberOfY(String childObjDn, String parentObjDn, String memberAttr, String ldapUser, String ldapHost, String ldapPort, String ldapPassword) {
         
        InitialDirContext ctx = connectToLdap(ldapUser, ldapHost, ldapPort, ldapPassword);
        if (findObjectWithDnAndValue(ctx, memberAttr, childObjDn, parentObjDn) != null) {
            closeLdapConnection(ctx);
            return "True";
        }
        closeLdapConnection(ctx);
        return "False";
    }
 
 
     
    /** Private Methods **/
    private static InitialDirContext connectToLdap(String ldapUser, String ldapHost, String ldapPort, String ldapPassword) {
        String initctx = "com.sun.jndi.ldap.LdapCtxFactory";
        String authenticationType = "simple";
 
        String ldapAddress = "ldap://" + ldapHost + ":" + ldapPort;
        Hashtable<String, String> env = new Hashtable<String, String>();
 
        env.put(Context.INITIAL_CONTEXT_FACTORY, initctx);
        env.put(Context.PROVIDER_URL, ldapAddress);
        env.put(Context.SECURITY_AUTHENTICATION, authenticationType);
        env.put(Context.SECURITY_PRINCIPAL, ldapUser);
        env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
 
        InitialDirContext ctx = null;
        try {
            ctx = new InitialDirContext(env);
            return ctx;
 
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }
     
    private static void closeLdapConnection(DirContext ctx) {
        try {
            ctx.close();
        } catch (NamingException e) {
            // No need to tell us that we cannot close the connection, it would be terminated anyway.
        }
    }
     
    private static SearchResult findObjectWithDn(DirContext ctx, String attributeName, String objectDn) {
 
        String searchFilter = generateSearchFilter(attributeName, objectDn);
        String ldapSearchBase = parseDcFromDn(objectDn);
        return findObject(ctx, searchFilter, ldapSearchBase);
    }
     
    private static SearchResult findObjectWithDnAndValue(DirContext ctx, String attributeName, String attributeValue, String objectDn) {
 
        String searchFilter = generateSearchFilter(attributeName, attributeValue);
        String ldapSearchBase = parseDcFromDn(objectDn);
        return findObject(ctx, searchFilter, ldapSearchBase);
 
    }
     
    private static SearchResult findObject(DirContext ctx, String searchFilter, String ldapSearchBase) {
         
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
 
        NamingEnumeration<SearchResult> results;
        try {
            results = ctx.search(ldapSearchBase, searchFilter, searchControls);
        } catch (NamingException e) {
            return null;
        }
 
        SearchResult searchResult = null;
        if(results.hasMoreElements()) {
             searchResult = (SearchResult) results.nextElement();
        }
        return searchResult;
         
    }
     
    private static String generateSearchFilter(String attributeName, String value) {
        String returnString = "(" + attributeName + "=" + value + ")";
        return returnString;
    }
     
    private static String parseDcFromDn(String objectDn) {
        String pattern = "^cn=[^,]*,(?:(?:(?:cn|ou)=[^,]+,?)+),((?:dc=[^,]+,?)+)$";
        objectDn = objectDn.toLowerCase();
 
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(objectDn);
         
        if (m.find()) {
            return m.group(1).toString();
        }
        return objectDn;
    }
}
