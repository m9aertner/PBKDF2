<%@ page language="java"
         import="javax.naming.*,
                 javax.sql.*,
                 java.sql.*" %>
<jsp:include page="WEB-INF/jspx/header.jsp" />

<h1>Add User Database Record</h1>
<%
    String username = request.getParameter("username");
    if( username == null ) {
        username = "john";
    }
    String keyblob = request.getParameter("keyblob");

    // Ignore proper resource management for now... 
	DataSource ds = InitialContext.doLookup("java:jboss/datasources/ExampleDS");
	Connection con = ds.getConnection();
	PreparedStatement ps = null; 

    if( keyblob == null || "".equals(keyblob) ) {
	    ps = con.prepareStatement("DELETE FROM Users WHERE username=?");
	    ps.setString(1, username);
	} else {
	    ps = con.prepareStatement("MERGE INTO Users (username, password) VALUES (?, ?)");
	    ps.setString(1, username);
	    ps.setString(2, keyblob);
	}

	ps.executeUpdate();
	con.close();
%>

<p>
Done.
</p>
<p>
<a href="index.jsp">Back</a>
</p>

<jsp:include page="WEB-INF/jspx/footer.jsp" />
