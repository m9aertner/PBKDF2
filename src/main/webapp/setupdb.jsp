<%@ page language="java"
         import="javax.naming.*,
                 javax.sql.*,
                 java.sql.*" %>
<jsp:include page="WEB-INF/jspx/header.jsp" />

<h1>Create Database Tables</h1>
<%
    // Ignore proper resource management for now... 
    DataSource ds = InitialContext.doLookup("java:jboss/datasources/ExampleDS");
    Connection con = ds.getConnection();
    con.prepareStatement("CREATE TABLE Users(username VARCHAR(255), password VARCHAR(255), PRIMARY KEY (username))").executeUpdate();
    con.close();
%>

<p>
Done.
</p>
<p>
<a href="index.jsp">Back</a>
</p>

<jsp:include page="WEB-INF/jspx/footer.jsp" />
