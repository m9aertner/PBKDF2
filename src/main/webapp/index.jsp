<%@ page language="java" %>
<jsp:include page="WEB-INF/jspx/header.jsp" />

<h2>Setup</h2>
First create the small H2 database table "Users". 
<form method="POST" action="setupdb.jsp">
<input type="submit" value="Create Users Table" />
</form>

<h2>Create a User</h2>

Enter records into the database table. The pre-set password hash is derived from &quot;password&quot;.

<form method="POST" action="adduser.jsp">
<input type="text" name="username" value="john" />
<input type="text" name="keyblob" size="64" value="73616C74:1:0c60c80f961f0e71f3a9b524af6012062fe037a6" /><br />
<input type="submit" value="Add User" />
</form>

To create your own "password", you may use the <i>main class</i> in PBKDF2.jar.
Note that the PBKDF2 code is <b>not</b> included nor required in the WebApp, so
a plaintext entry is not offered. It would be a one-liner to add it, though,
assuming the JAR would be included. 
<pre>
&gt; java -jar build\libs\PBKDF2-1.1.0.jar "your password"
7008119CDC9AD6D9:1000:D213E20E346F4A762350C530BBBAD375ABA3FEB6
</pre>

<h2>Access protected resource</h2>

Click <a href="hello.jsp">here</a> for a request to secured <a href="hello.jsp">hello.jsp</a>.
You should see your browser asking for BASIC authentication information.
Enter &quot;john&quot; / &quot;password&quot; in the authentication dialog.

<h2>Log Out</h2>
<%
    String host = request.getHeader("Host");
    String context = request.getContextPath();
    if( context == null ) {
        context = "";
    }
%>
Click here: <a href="http://no-such-user@<%= host + context %>/hello.jsp">no-such-user@hello.jsp</a>.

<jsp:include page="WEB-INF/jspx/footer.jsp" />
