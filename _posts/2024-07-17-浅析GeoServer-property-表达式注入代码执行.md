---
layout:     post
title:      浅析GeoServer-property-表达式注入代码执行
subtitle:   CVE-2024-36401
date:       2024-04-17
author:     lyk
header-img: img/post-bg-mma-1.png
catalog: true
tags:
    - java
---

# 0x01 前言

GeoServer 是一个开源服务器，允许用户共享和编辑地理空间数据，依赖 GeoTools 库来处理地理空间数据。

受影响的版本中 GeoTools 库的 API 在处理要素类型的属性名称时，会将这些属性名称不安全地传递给 commons-jxpath 库进行解析，由于 commons-jxpath 库在解析 XPath 表达式时可以执行任意代码，从而导致未经身份验证的用户能够利用特定的 OGC 请求参数远程执行代码。

# 0x02 漏洞复现分析

从公告来看，漏洞来源于geotools这个库使用apache xpath解析xpath导致的问题

https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv

https://github.com/geotools/geotools/pull/4797

https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w

之后简单看看geotools的commit可以发现有很多

https://github.com/geotools/geotools/pull/4797/commits/e53e5170ba71521728875a436c80616cfb03c1e8

比如，从上到下依次看有很多能触发的方式，这里我们简单有个印象即可

```java
rg.geotools.appschema.util.XmlXpathUtilites.getXPathValues(NamespaceSupport, String, Document)
org.geotools.appschema.util.XmlXpathUtilites.countXPathNodes(NamespaceSupport, String, Document)
org.geotools.appschema.util.XmlXpathUtilites.getSingleXPathValue(NamespaceSupport, String, Document)
org.geotools.data.complex.expression.FeaturePropertyAccessorFactory.FeaturePropertyAccessor.get(Object, String, Class<T>)
org.geotools.data.complex.expression.FeaturePropertyAccessorFactory.FeaturePropertyAccessor.set(Object, String, Object, Class)
org.geotools.data.complex.expression.MapPropertyAccessorFactory.new PropertyAccessor() {...}.get(Object, String, Class<T>)
org.geotools.xsd.StreamingParser.StreamingParser(Configuration, InputStream, String)
```

再看geoserver的公告，以下这些都能被利用

![image-20240703162342214](..\img\image-20240703162342214.png)

首先以最简单的GetPropertyValue为例，从官方文档可以看到具体的使用方法，https://docs.geoserver.org/latest/en/user/services/wfs/reference.html#getpropertyvalue

![image-20240703224128239](\img\image-20240703224128239.png)

我比较懒找了个之前的老环境代码方便我本地调试

https://versaweb.dl.sourceforge.net/project/geoserver/GeoServer/2.21.3/geoserver-2.21.3-war.zip?viasf=1

可以看到在`org.geoserver.wfs.GetPropertyValue#run`，红框中的代码从请求中获取了`valuereference`参数，之后调用工厂类的property方法获取`PropertyName`对象

![image-20240703224938791](\img\image-20240703224938791.png)

我们来看看这个工厂类的调用，直接返回一个被`AttributeExpressionImpl`包装的对象

![image-20240703230134192](\img\image-20240703230134192.png)

同时实例化时将参数赋给attPath

![image-20240703230505213](\img\image-20240703230505213.png)

接下来再来看看evaluate的调用，在这里会通过`PropertyAccessors.findPropertyAccessors`获取合适的属性访问器，之后遍历调用其`get`方法，其中就包括了`org.geotools.data.complex.expression.FeaturePropertyAccessorFactory.FeaturePropertyAccessor#get`，官方公告列出来的就有这个

![image-20240703232348317](\img\image-20240703232348317.png)

在下面的代码中可以解析xpath表达式，因此从上面分析下来这个xpath就是valuereference中的值，整个流程也就走通了

![image-20240703233055237](\img\image-20240703233055237.png)

‍

# 0x03 路由分析

同时像我这种好奇宝宝一般是比较好奇一些路由方法的调用，就比如为什么通过参数中的`request`能调用对应方法，这个项目主体框架是spring

以我下载的war为例，先看web.xml，通常而言这就是我们项目的主入口，但是点进去一看，在配置文件中大多只有Servlet的过滤器链的配置，而没有具体接口的配置，当然唯一的可以看到将请求都通过spring的DispatcherServlet派发

```xml
<!-- spring dispatcher servlet, dispatches all incoming requests -->
<servlet>
  <servlet-name>dispatcher</servlet-name>
  <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
</servlet>
 
<!-- single mapping to spring, this only works properly if the advanced dispatch filter is 
     active -->
<servlet-mapping>
    <servlet-name>dispatcher</servlet-name>
    <url-pattern>/*</url-pattern>
</servlet-mapping>
```

因此接下来我们就得看看，spring项目的一些其他配置文件，比如`\geoserver\WEB-INF\lib\gs-wfs-2.21.3.jar!\applicationContext.xml`，看着这个配置文件就会更为亲切，当然又扯远了，回到正文

在这个项目中，`org.geoserver.ows.Dispatcher`继承了`AbstractController`并实现了`handleRequestInternal`方法

```java
protected ModelAndView handleRequestInternal(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws Exception {
    this.preprocessRequest(httpRequest);
    Request request = new Request();
    request.setHttpRequest(httpRequest);
    request.setHttpResponse(httpResponse);
    Service service = null;

    try {
        try {
            request = this.init(request);
            REQUEST.set(request);

            Object result;
            try {
                service = this.service(request);
            } catch (Throwable var11) {
                this.exception(var11, (Service)null, request);
                result = null;
                return (ModelAndView)result;
            }

            if (request.getError() != null) {
                throw request.getError();
            }

            Operation operation = this.dispatch(request, service);
            request.setOperation(operation);
            if (request.isSOAP()) {
                this.flagAsSOAP(operation);
            }

            result = this.execute(request, operation);
            if (result != null) {
                this.response(result, request, operation);
                return null;
            }
        } catch (Throwable var12) {
            if (isSecurityException(var12)) {
                throw (Exception)var12;
            }

            this.exception(var12, service, request);
        }

        return null;
    } finally {
        this.fireFinishedCallback(request);
        REQUEST.remove();
    }
}

Object execute(Request req, Operation opDescriptor) throws Throwable {
    Service serviceDescriptor = opDescriptor.getService();
    Object serviceBean = serviceDescriptor.getService();
    Object[] parameters = opDescriptor.getParameters();
    Object result = null;

    try {
        if (serviceBean instanceof DirectInvocationService) {
            String operationName = opDescriptor.getId();
            result = ((DirectInvocationService)serviceBean).invokeDirect(operationName, parameters);
        } else {
            Method operation = opDescriptor.getMethod();
            result = operation.invoke(serviceBean, parameters);
        }
    } catch (Exception var8) {
        if (var8.getCause() != null) {
            throw var8.getCause();
        }

        throw var8;
    }

    return this.fireOperationExecutedCallback(req, opDescriptor, result);
}

Operation dispatch(Request req, Service serviceDescriptor) throws Throwable {
    if (req.getRequest() == null) {
        String msg = "Could not determine geoserver request from http request " + req.getHttpRequest();
        throw new ServiceException(msg, "MissingParameterValue", "request");
    } else {
        boolean exists = this.operationExists(req, serviceDescriptor);
        if (!exists && req.getKvp().get("request") != null) {
            req.setRequest(normalize(KvpUtils.getSingleValue(req.getKvp(), "request")));
            exists = this.operationExists(req, serviceDescriptor);
        }

        Object serviceBean = serviceDescriptor.getService();
        Method operation = OwsUtils.method(serviceBean.getClass(), req.getRequest());
        if (operation != null && exists) {
            Object[] parameters = new Object[operation.getParameterTypes().length];

            for(int i = 0; i < parameters.length; ++i) {
                Class<?> parameterType = operation.getParameterTypes()[i];
                if (parameterType.isAssignableFrom(HttpServletRequest.class)) {
                    parameters[i] = req.getHttpRequest();
                } else if (parameterType.isAssignableFrom(HttpServletResponse.class)) {
                    parameters[i] = req.getHttpResponse();
                } else if (parameterType.isAssignableFrom(InputStream.class)) {
                    parameters[i] = req.getHttpRequest().getInputStream();
                } else if (parameterType.isAssignableFrom(OutputStream.class)) {
                    parameters[i] = req.getHttpResponse().getOutputStream();
                } else {
                    Object requestBean = null;
                    Throwable t = null;
                    boolean kvpParsed = false;
                    boolean xmlParsed = false;
                    if (req.getKvp() != null && req.getKvp().size() > 0) {
                        try {
                            requestBean = this.parseRequestKVP(parameterType, req);
                            kvpParsed = true;
                        } catch (Exception var14) {
                            t = var14;
                        }
                    }

                    if (req.getInput() != null) {
                        requestBean = this.parseRequestXML(requestBean, req.getInput(), req);
                        xmlParsed = true;
                    }

                    if (requestBean == null) {
                        if (t != null) {
                            throw t;
                        }

                        if ((!kvpParsed || !xmlParsed) && (kvpParsed || xmlParsed)) {
                            if (kvpParsed) {
                                throw new ServiceException("Could not parse the KVP for: " + parameterType.getName());
                            }

                            throw new ServiceException("Could not parse the XML for: " + parameterType.getName());
                        }

                        throw new ServiceException("Could not find request reader (either kvp or xml) for: " + parameterType.getName() + ", it might be that some request parameters are missing, please check the documentation");
                    }

                    Method setBaseUrl = OwsUtils.setter(requestBean.getClass(), "baseUrl", String.class);
                    if (setBaseUrl != null) {
                        setBaseUrl.invoke(requestBean, ResponseUtils.baseURL(req.getHttpRequest()));
                    }

                    if (requestBean != null) {
                        if (req.getService() == null) {
                            req.setService(this.lookupRequestBeanProperty(requestBean, "service", false));
                        }

                        if (req.getVersion() == null) {
                            req.setVersion(normalizeVersion(this.lookupRequestBeanProperty(requestBean, "version", false)));
                        }

                        if (req.getOutputFormat() == null) {
                            req.setOutputFormat(this.lookupRequestBeanProperty(requestBean, "outputFormat", true));
                        }

                        parameters[i] = requestBean;
                    }
                }
            }

            if (this.citeCompliant) {
                if (!"GetCapabilities".equalsIgnoreCase(req.getRequest())) {
                    if (req.getVersion() == null) {
                        throw new ServiceException("Could not determine version", "MissingParameterValue", "version");
                    }

                    if (!req.getVersion().matches("[0-99].[0-99].[0-99]")) {
                        throw new ServiceException("Invalid version: " + req.getVersion(), "InvalidParameterValue", "version");
                    }

                    boolean found = false;
                    Version version = new Version(req.getVersion());
                    Iterator var20 = this.loadServices().iterator();

                    while(var20.hasNext()) {
                        Service service = (Service)var20.next();
                        if (version.equals(service.getVersion())) {
                            found = true;
                            break;
                        }
                    }

                    if (!found) {
                        throw new ServiceException("Invalid version: " + req.getVersion(), "InvalidParameterValue", "version");
                    }
                }

                if (req.getService() == null) {
                    throw new ServiceException("Could not determine service", "MissingParameterValue", "service");
                }
            }

            Operation op = new Operation(req.getRequest(), serviceDescriptor, operation, parameters);
            return this.fireOperationDispatchedCallback(req, op);
        } else {
            String msg = "No such operation " + req;
            throw new ServiceException(msg, "OperationNotSupported", req.getRequest());
        }
    }
}
```

从上面的代码中我们很容易发现，通过dispatch的代码我们很容易发现会通过这个request对象查找对应的方法，获取到后之后再通过execute执行，因此答案也就有了

![image-20240704000520770](\img\image-20240704000520770.png)

当然这个方法可以仔细看看对请求的解析部分，里面对多种请求方式的解析也可以了解了解

一些具体的流程可参考如下逻辑

![image-20240704103211697](\img\image-20240704103211697.png)



# 0x04 结语

相比较其他利用还是觉得GetProperty的利用比较舒服，不像`GetFeature`之类的里面到处都是触发点，会导致xpath被解析很多次，当然poc就不贴了学习思路为主，在GetProperty中也有一个比较好用的对抗流量设备的点

在这里可以看到在获取参数时会把`[]`中的内容替换为空，但很可惜是贪婪匹配(至少我这个老代码是这样的)，不过也可以拿来做一些利用，比如我们的`java.lang.Runtime`可以写成`java.lang.Ru[Hacked By Y4]ntime`

```java
PropertyName propertyNameNoIndexes = this.filterFactory.property(request.getValueReference().replaceAll("\\[.*\\]", ""), this.getNamespaceSupport());
```

依然是可以触发的

![image-20240704001829248](\img\image-20240704001829248.png)



# 0x05 参考

[https://github.com/vulhub/vulhub/tree/master/geoserver/CVE-2024-36401](https://forum.butian.net/share/2857)

[CVE-2024-36401](https://y4tacker.github.io/2024/07/03/year/2024/7/浅析GeoServer-property-表达式注入代码执行-CVE-2024-36401/)
