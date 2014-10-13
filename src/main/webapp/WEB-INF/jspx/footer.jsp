<%@ page language="java" %>
<hr />
<p>
<%
    long t = System.currentTimeMillis() - Long.valueOf((String)request.getAttribute("ts-start"));
%>
<%= new java.text.SimpleDateFormat("YYYY-MM-dd HH:mm:ss").format(new java.util.Date()) %>
(<%= t %>ms)
</p>
</body>
</html>
