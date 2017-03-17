import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import sun.misc.BASE64Encoder;

class FilePartInfo {
	long m_offset;
	long m_dataSize;
	int m_isSend = 0;

	int SetSend() {
		m_isSend = 1;
		return 0;
	}

	int Init(long offset, long dataSize) {
		return 0;
	}
}

class PartUploadThread extends Thread  {
	VodCall m_upload;
	ArrayList<Integer> m_arrPartIndex = new ArrayList<Integer>();
	int m_iRet = 0;
	int m_errIndex = -1;
	int m_iThreadId = 0;
	public PartUploadThread(VodCall upload, int iThreadId) {
		m_upload = upload;
		m_iThreadId = iThreadId;
	}
	int AddPartIndex(int i) {
		m_arrPartIndex.add(i);
		return 0;
	}
	public void run() {
		for (int i = 0; i < m_arrPartIndex.size(); i++) {
			try {
				m_iRet = m_upload.PartUpload(m_arrPartIndex.get(i));
				if (m_iRet < 0) {
					m_errIndex = i;
					break;
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}

public class VodCall {
	String m_strSecId;
	String m_strSecKey;
	String m_strFilePath;
	String m_strFileName;
	String m_strFileSha;
	String m_strRegion = "gz";
	String m_strReqHost;
	String m_strReqPath;
	
	String m_strUploadReqHost = "vod2.qcloud.com";
	String m_strUploadReqPath = "/v3/index.php";
	
	String m_strRestApiReqHost = "vod.api.qcloud.com";
	String m_strRestApiReqPath = "/v2/index.php";
	String m_strFileType;
	String m_strFileId;
	String m_strUrl;
	
	String m_strExtra = "";
	
	public ArrayList<FilePartInfo> m_arrPartInfo;
	ArrayList<PartUploadThread> m_arrThreadList;
	ArrayList<String> m_arrTags;
	TreeMap<String, Object> m_mapExtras = new TreeMap<String, Object>();
	int m_isTrans = 0;
	int m_isScreenShot = 0;
	int m_isWaterMark = 0;
	int m_iClassId = 0;
	int m_iExpireTime = 0;
	long m_qwFileSize = 0;
	long m_dataSize = 512 * 1024;
	int m_iUgcRandom = 0;
	
	private static final String CONTENT_CHARSET = "UTF-8";
	private static final String HMAC_ALGORITHM = "HmacSHA1";
	private static final int MAX_RETRY_TIME = 3;
	
	public static final int USAGE_UPLOAD = 0;
	public static final int USAGE_UGC_UPLOAD = 1;
	public static final int USAGE_VOD_REST_API_CALL = 2;
	
	public String m_strErrMsg = "";
	
	private int m_iThreadNum = 1;
	
	private long m_qwStartTime;
	private long m_qwEndTime;
	private int m_iUsage = 0;
	private int m_iIsEcho = 0;
	
	
	public VodCall() {
	}
	
	public int OpenEcho() {
		m_iIsEcho = 1;
		return 0;
	}
	
	private int Echo(String strMsg) {
		if (m_iIsEcho == 1)
			System.out.println(strMsg);
		return 0;
	}
	
	int Init(String secId, String secKey, int iUsage, int threadNum) {
		m_strSecId = secId;
		m_strSecKey = secKey;
		m_arrTags = new ArrayList<String>();
		m_arrPartInfo = new ArrayList<FilePartInfo>();
		if (threadNum < 100 && threadNum >= 1) 
			m_iThreadNum = threadNum;
		
		m_arrThreadList = new ArrayList<PartUploadThread>();
		for (int i = 0; i < m_iThreadNum; i++) {
			m_arrThreadList.add(new PartUploadThread(this, i));
		}
		m_iUgcRandom = new Random().nextInt(java.lang.Integer.MAX_VALUE);
		this.m_qwStartTime = System.currentTimeMillis() / 1000;
		m_iUsage = iUsage;
		
		if (iUsage == this.USAGE_VOD_REST_API_CALL) {
			m_strReqHost = this.m_strRestApiReqHost;
			m_strReqPath = this.m_strRestApiReqPath;
		} else if (iUsage == this.USAGE_UPLOAD || iUsage == this.USAGE_UGC_UPLOAD) {
			m_strReqHost = this.m_strUploadReqHost;
			m_strReqPath = this.m_strUploadReqPath;
		} else {
			return -1;
		}
		return 0;
	}

	public static String getSign(String strContext, String strKey) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		String sig = null;
		Mac mac = Mac.getInstance("HmacSHA1");
		SecretKeySpec secretKey = new SecretKeySpec(strKey.getBytes("UTF-8"), mac.getAlgorithm());

		mac.init(secretKey);
		byte[] hash = mac.doFinal(strContext.getBytes("UTF-8"));
		// base64
		String strSign = new String(new BASE64Encoder().encode(hash).getBytes());
		return strSign;
	}
	
	int InitCommPara(TreeMap<String, Object> mapVals) {
		mapVals.put("Region", m_strRegion);
		mapVals.put("SecretId", m_strSecId);
		mapVals.put("fileSha", m_strFileSha);
		mapVals.put("Timestamp", System.currentTimeMillis() / 1000);
		mapVals.put("Nonce", new Random().nextInt(java.lang.Integer.MAX_VALUE));
		return 0;
	}
	
	JSONObject CallRestApi(TreeMap<String, Object> mapVals) {
		if (this.m_iUsage != this.USAGE_VOD_REST_API_CALL)
		{
			Echo("error");
			return null;
		}
		Echo("call req");
		mapVals.put("Region", m_strRegion);
		mapVals.put("SecretId", m_strSecId);
		mapVals.put("Timestamp", System.currentTimeMillis() / 1000);
		mapVals.put("Nonce", new Random().nextInt(java.lang.Integer.MAX_VALUE));
		String strSign = this.GetReqSign(mapVals);
		try {
			String strReq = this.GetReqUrl(mapVals, strSign);
			Echo("req " + strReq);
			return this.DoHttpReq(strReq, null, 0);
		} catch (Exception e){
		}
		return null;
	}
	
	int SetTransCfg(int isTrans, int isScreenShot, int isWaterMark) {
		m_isTrans = isTrans;
		m_isScreenShot = isScreenShot;
		m_isWaterMark = isWaterMark;
		return 0;
	}

	int SetExpireTime(int iExpireTime) {
		m_iExpireTime = iExpireTime;
		return 0;
	}
	int AddFileTag(String strTag) {
		m_arrTags.add(strTag);
		return 0;
	}
	
	int AddExtraPara(String key, Object val) {
		m_mapExtras.put("extra." + key, val);
		return 0;
	}

	int SetFileInfo(String strFilePath, String strFileName, String strFileType, int classId) {
		m_strFilePath = strFilePath;
		m_strFileName = strFileName;
		m_strFileType = strFileType;
		m_iClassId = classId;
		m_arrTags.clear();
		File stFile = new File(m_strFilePath);
		if (!stFile.exists()) {
			return -4001;
		}
		m_strFileSha = calFileSha(m_strFilePath);
		return 0;
	}
	
	public int SetFileExtra(String strExtra) {
		m_strExtra = strExtra;
		return 0;
	}

	public static String stringToSHA(String str) {
		try {
			byte[] strTemp = str.getBytes();
			MessageDigest mdTemp = MessageDigest.getInstance("SHA-1"); // SHA-256
			mdTemp.update(strTemp);
			return toHexString(mdTemp.digest());
		} catch (Exception e) {
			return null;
		}
	}

	public static String calFileSha(String filePath) {
		InputStream inputStream = null;
		try {
			inputStream = new FileInputStream(filePath);
			return calStreamShaMd5(inputStream, "SHA-1");
		} catch (Exception e) {
			return null;
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public static String calStreamShaMd5(InputStream inputStream, String strMethod) {
		try {
			MessageDigest mdTemp = MessageDigest.getInstance(strMethod); // SHA-256
			byte[] buffer = new byte[1024];
			int numRead = 0;
			while ((numRead = inputStream.read(buffer)) > 0) {
				mdTemp.update(buffer, 0, numRead);
			}
			return toHexString(mdTemp.digest());
		} catch (Exception e) {
			return null;
		}
	}

	private static String toHexString(byte[] md) {
		char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
		int j = md.length;
		char str[] = new char[j * 2];
		for (int i = 0; i < j; i++) {
			byte byte0 = md[i];
			str[2 * i] = hexDigits[byte0 >>> 4 & 0xf];
			str[i * 2 + 1] = hexDigits[byte0 & 0xf];
		}
		return new String(str);
	}

	String GetReqSign(TreeMap<String, Object> mapVals) {
		if (m_iUsage == this.USAGE_UGC_UPLOAD)
			return GetUgcExSign();
		if (m_iUsage == this.USAGE_UPLOAD)
			InitCommPara(mapVals);
		String strSign = "";
		try {
			String reqStr = "";
			for (String key : mapVals.keySet()) {
				if (reqStr.isEmpty()) {
					reqStr += '?';
				} else {
					reqStr += '&';
				}
				//reqStr += key + '=' + java.net.URLEncoder.encode(mapVals.get(key).toString(), "utf-8").replace("*", "%2A").replace("+", "%20").replace("%7E", "~");
				reqStr += (key + '=' + mapVals.get(key).toString());
			}
			String contextStr = "";
			if (m_iUsage == this.USAGE_UPLOAD)
				contextStr += "POST";
			else if (m_iUsage == this.USAGE_VOD_REST_API_CALL)
				contextStr += "GET";
			contextStr += m_strReqHost;
			contextStr += m_strReqPath;
			contextStr += reqStr;

			String s = contextStr;
			String sig = null;
			Mac mac = Mac.getInstance(HMAC_ALGORITHM);
			SecretKeySpec secretKey = new SecretKeySpec(m_strSecKey.getBytes(CONTENT_CHARSET), mac.getAlgorithm());
			mac.init(secretKey);
			byte[] hash = mac.doFinal(contextStr.getBytes(CONTENT_CHARSET));
			// base64
			strSign = new String(new BASE64Encoder().encode(hash).getBytes());
			Echo(contextStr);
//			getSign(s, m_strSecKey);
		} catch (Exception e) {
			return "";
		}
		return strSign;
	}
    public static byte[] byteMerger(byte[] byte_1, byte[] byte_2){  
        byte[] byte_3 = new byte[byte_1.length+byte_2.length];  
        System.arraycopy(byte_1, 0, byte_3, 0, byte_1.length);  
        System.arraycopy(byte_2, 0, byte_3, byte_1.length, byte_2.length);  
        return byte_3;  
    } 
    
	//本函数需要改为远程调用，将 fileName fileSha fileType等字段，通过http请求发到后台svr，由后台svr算出strSign返回给前端
    //本函数仅作为示例
    //参考协议
	String GetUgcExSign() {
		String strSign = "";
		String contextStr = "";
		//签名超时时间
		long endTime = (m_qwStartTime + 3600*24*2);
		try {
		//这些参数，由客户端带到svr
		contextStr += "f=" + java.net.URLEncoder.encode(m_strFileName, "utf8");
		contextStr += "&fs=" + this.m_strFileSha;
		contextStr += "&ft=" + this.m_strFileType;
		
		//这些参数控制放在后台来生成
		contextStr += "&t=" + this.m_qwStartTime;
		contextStr += "&e=" + endTime;
		contextStr += "&r=" + this.m_iUgcRandom;
		contextStr += "&s=" + java.net.URLEncoder.encode(this.m_strSecId, "utf8");
		contextStr += "&uid=" + "1";
		contextStr += "&tc=" + this.m_isTrans;
		contextStr += "&ss=" + this.m_isScreenShot;
		contextStr += "&wm=" + this.m_isWaterMark;
		
		if (this.m_iClassId != 0)
		{
			contextStr += "&cid=" + this.m_iClassId;
		}
		
		String s = contextStr;
		String sig = null;
		Mac mac = Mac.getInstance(HMAC_ALGORITHM);
		SecretKeySpec secretKey = new SecretKeySpec(m_strSecKey.getBytes(CONTENT_CHARSET), mac.getAlgorithm());
		mac.init(secretKey);
		byte[] hash = mac.doFinal(contextStr.getBytes(CONTENT_CHARSET));
	    byte[] sigBuf = byteMerger(hash, contextStr.getBytes("utf8"));
		// base64
		strSign = new String(new BASE64Encoder().encode(sigBuf).getBytes());
		//Echo(strSign);
		} catch (Exception e) {
			return "";
		}
		return strSign;
	}

	public String GetReqUrl(TreeMap<String, Object> mapVals, String strSign) throws UnsupportedEncodingException {
		String reqStr = "";
		for (String key : mapVals.keySet()) {
			if (reqStr.isEmpty()) {
				reqStr += '?';
			} else {
				reqStr += '&';
			}
			reqStr += key + '=' + java.net.URLEncoder.encode(mapVals.get(key).toString(), "utf8").replace("*", "%2A").replace("+", "%20").replace("%7E", "~");
		}
		reqStr += ("&" + "Signature=" + URLEncoder.encode(strSign, "utf8"));
		return "https://" + m_strReqHost + m_strReqPath + reqStr;
	}

	// 生成分片信息
	int GeneratePartInfo() {
		long partNum = m_qwFileSize / m_dataSize;
		for (int i = 0; i < partNum; i++) {
			FilePartInfo stInfo = new FilePartInfo();
			stInfo.m_dataSize = m_dataSize;
			stInfo.m_isSend = 0;
			stInfo.m_offset = m_dataSize * i;
			this.m_arrPartInfo.add(stInfo);
		}
		if (partNum * m_dataSize < m_qwFileSize) {
			FilePartInfo stInfo = new FilePartInfo();
			stInfo.m_dataSize = m_qwFileSize - partNum * m_dataSize;
			stInfo.m_isSend = 0;
			stInfo.m_offset = partNum * m_dataSize;
			this.m_arrPartInfo.add(stInfo);
		}
		return 0;
	}

	public JSONObject DoHttpReq(String strReq, byte[] data, int size) throws IOException, JSONException {
		URL url = new URL(strReq);
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();

		// 设置http连接属性
		if (this.m_iUsage == this.USAGE_VOD_REST_API_CALL)
			connection.setRequestMethod("GET");
		else 
			connection.setRequestMethod("POST");
		connection.setRequestProperty("accept", "**");
		connection.setRequestProperty("connection", "Keep-Alive");
		connection.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setReadTimeout(1000 * 1000);
		connection.setConnectTimeout(1000 * 1000);
		connection.connect();
		if (size != 0) {
			BufferedOutputStream out = new BufferedOutputStream(connection.getOutputStream());
			out.write(data, 0, size);
			out.close();
		}
		// connection.connect();

		BufferedReader in = null;
		String result = "";
		JSONObject jsonobj = null;

		InputStream inputStream = connection.getInputStream();
		in = new BufferedReader(new InputStreamReader(inputStream));

		String line;
		while ((line = in.readLine()) != null) {
			line = new String(line.getBytes(), "utf-8");
			result += line;
		}
		// in.close();
		// connection.disconnect();
		Echo(result);

		jsonobj = new JSONObject(result);

		return jsonobj;
	}

	public int SmallFileUpload() throws Exception {
		int retryLimit = MAX_RETRY_TIME;
		int iIndex = 0;
		FilePartInfo filePart = new FilePartInfo();
		filePart.m_dataSize = this.m_qwFileSize;
		filePart.m_isSend = 0;
		filePart.m_offset = 0;
		RandomAccessFile stFile = new RandomAccessFile(m_strFilePath, "r");
		m_qwFileSize = stFile.length();
		filePart.m_dataSize = this.m_qwFileSize;
		m_arrPartInfo.add(filePart);
		TreeMap<String, Object> mapVals = new TreeMap<String, Object>();
		
		if (this.m_mapExtras.size() > 0) {
			mapVals.putAll(m_mapExtras);
		}
		while (true) {
			FilePartInfo partInfo = m_arrPartInfo.get(iIndex);
			if (partInfo.m_isSend == 1) {
				return 0;
			}
			stFile.seek(partInfo.m_offset);
			byte[] buf = new byte[(int) partInfo.m_dataSize];
			int ret = stFile.read(buf);
			stFile.close();
			if (ret != partInfo.m_dataSize) {
				Echo("retCode : " + ret +" dataSize : " + partInfo.m_dataSize);
				return -2001;
			}
			mapVals.put("Action", "SmallFileUpload");
			mapVals.put("fileSize", m_qwFileSize);
			mapVals.put("fileName", m_strFileName);
			mapVals.put("fileType", m_strFileType);
			mapVals.put("storeTime", m_iExpireTime);
			//mapVals.put("isTranscode", m_isTrans);
			//mapVals.put("isScreenshot", m_isScreenShot);
			//mapVals.put("isWatermark", m_isWaterMark);
			//mapVals.put("classId", m_iClassId);
			mapVals.put("dataSize", partInfo.m_dataSize);
			mapVals.put("offset", partInfo.m_offset);
			InputStream stInput = new ByteArrayInputStream(buf);
			String strMd5 = calStreamShaMd5(stInput, "MD5");
			mapVals.put("dataMd5", strMd5);

			String strSign = GetReqSign(mapVals);
			String strReq = GetReqUrl(mapVals, strSign);
			Echo(strReq);
			JSONObject jsonobj= null;
			try {
				jsonobj = DoHttpReq(strReq, buf, (int) (partInfo.m_dataSize));
			} catch (Exception e) {
				if (retryLimit > 0) {
					retryLimit--;
					continue;
				}
				return -2002;
			}
			int retCode = jsonobj.getInt("code");
			if (retCode == 0) {
				partInfo.m_isSend = 1;
				m_strFileId = jsonobj.getString("fileId");
				m_strUrl = jsonobj.getString("url");
			} else {
				int canRetry = jsonobj.getInt("canRetry");
				if (canRetry == 1 && retryLimit > 0) {
					retryLimit--;
					continue;
				}
				return -2003;
			}
			return 0;
		}
	}
	
	public int PartUpload(int iIndex) throws Exception {
		int retryLimit = MAX_RETRY_TIME;
		TreeMap<String, Object> mapVals = new TreeMap<String, Object>();		
		while (true) {
			FilePartInfo partInfo = m_arrPartInfo.get(iIndex);
			if (partInfo.m_isSend == 1) {
				return 0;
			}
			RandomAccessFile stFile = new RandomAccessFile(m_strFilePath, "r");
			stFile.seek(partInfo.m_offset);
			byte[] buf = new byte[(int) partInfo.m_dataSize];
			int ret = stFile.read(buf);
			stFile.close();
			if (ret != partInfo.m_dataSize) {
				Echo("code" + ret + partInfo.m_dataSize);
				return -2001;
			}
			if (m_iUsage == 1)
				mapVals.put("Action", "UploadPartEx");
			else 
				mapVals.put("Action", "UploadPart");
			mapVals.put("dataSize", partInfo.m_dataSize);
			mapVals.put("offset", partInfo.m_offset);
			InputStream stInput = new ByteArrayInputStream(buf);
			String strMd5 = calStreamShaMd5(stInput, "MD5");
			mapVals.put("dataMd5", strMd5);

			String strSign = GetReqSign(mapVals);
			String strReq = GetReqUrl(mapVals, strSign);
			Echo(strReq);
			JSONObject jsonobj= null;
			try {
				jsonobj = DoHttpReq(strReq, buf, (int) (partInfo.m_dataSize));
			} catch (Exception e) {
				if (retryLimit > 0) {
					retryLimit--;
					continue;
				}
				return -2002;
			}
			int retCode = jsonobj.getInt("code");
			if (retCode == 0) {
				partInfo.m_isSend = 1;
			} else {
				int canRetry = jsonobj.getInt("canRetry");
				if (canRetry == 1 && retryLimit > 0) {
					retryLimit--;
					continue;
				}
				return -2003;
			}
			return 0;
		}
	}

	public int FinishUpload() throws IOException, JSONException {
		int retryLimit = MAX_RETRY_TIME;
		TreeMap<String, Object> mapVals = new TreeMap<String, Object>();
		while (true) {
			if (m_iUsage == 1)
				mapVals.put("Action", "FinishUploadEx");
			else
				mapVals.put("Action", "FinishUpload");
			String strSign = GetReqSign(mapVals);
			if (strSign == "") {
				return -3001;
			}
			String strReq = GetReqUrl(mapVals, strSign);
			JSONObject jsonobj= null;
			try {
				jsonobj = DoHttpReq(strReq, null, 0);
			} catch (Exception e) {
				retryLimit--;
				continue;
			}
			int retCode = jsonobj.getInt("code");
			if (retCode == 0) {
				m_strFileId = jsonobj.getString("fileId");
			} else {
				int canRetry = jsonobj.getInt("canRetry");
				if (canRetry == 1 && retryLimit > 0) {
					if (retryLimit > 0) {
						retryLimit--;
						continue;
					}
					return -3002;
				}
				return -3003;
			}
			return 0;
		}
	}

	public int InitUpload() throws IOException, JSONException {
		int retryLimit = MAX_RETRY_TIME;
		TreeMap<String, Object> mapVals = new TreeMap<String, Object>();
		if (this.m_mapExtras.size() > 0) {
			mapVals.putAll(m_mapExtras);
		}
		while (true) {
			File stFile = new File(m_strFilePath);
			if (!stFile.exists()) {
				return -1001;
			}
			if (m_iUsage == 1)
				mapVals.put("Action", "InitUploadEx");
			else 
				mapVals.put("Action", "InitUpload");
			m_qwFileSize = stFile.length();
			mapVals.put("fileSize", m_qwFileSize);
			mapVals.put("dataSize", m_dataSize);
			mapVals.put("fileName", m_strFileName);
			mapVals.put("fileType", m_strFileType);
			mapVals.put("isTranscode", m_isTrans);
			mapVals.put("isScreenshot", m_isScreenShot);
			mapVals.put("isWatermark", m_isWaterMark);
			mapVals.put("classId", m_iClassId);
			mapVals.put("storeTime", m_iExpireTime);
			for (int i = 0; i < m_arrTags.size(); i++) {
				String key = "tag." + (i + 1);
				mapVals.put(key, m_arrTags.get(i));
			}

			if (m_strFileSha == null || m_strFileSha == "") {
				return -1001;
			}

			String strSign = GetReqSign(mapVals);
			if (strSign == "") {
				return -1003;
			}
			String strReq = GetReqUrl(mapVals, strSign);
			Echo(strReq);
			JSONObject jsonobj= null;
			try {
				jsonobj = DoHttpReq(strReq, null, 0);
			} catch (Exception e) {
				if (retryLimit > 0) {
					retryLimit--;
					continue;
				}
				return -1002;
			}
			int retCode = jsonobj.getInt("code");
			if (retCode == 2) {
				m_strFileId = jsonobj.getString("fileId");
			} else if (retCode == 1) {
				m_dataSize = jsonobj.getLong("dataSize");
				JSONArray existPart = jsonobj.getJSONArray("listParts");
				GeneratePartInfo();
				for (int i = 0; i < existPart.length(); i++) {
					JSONObject item = existPart.getJSONObject(i);
					long offset = item.getLong("offset");
					int index = (int) ((long) offset / (long) m_dataSize);
					m_arrPartInfo.get(index).m_isSend = 1;
				}
			} else if (retCode == 0) {
				GeneratePartInfo();
			} else {
				int canRetry = jsonobj.getInt("canRetry");
				if (canRetry == 1 && retryLimit > 0) {
					retryLimit--;
					continue;
				}
				return -1004;
			}
			return 0;
		}
	}
	
	public int Report(int code) throws IOException, JSONException {
		TreeMap<String, Object> mapVals = new TreeMap<String, Object>();
		mapVals.put("Action", "Report");
		mapVals.put("errCode", code);
		if (code == 0 && m_qwEndTime > m_qwStartTime) {
			mapVals.put("speed", m_qwFileSize/(m_qwEndTime - m_qwStartTime));
		} else {
			mapVals.put("speed", 0);
		}
        mapVals.put("fileId", m_strFileId);
        mapVals.put("platform", "java");
        mapVals.put("version", "1.0");
		String strSign = GetReqSign(mapVals);
		String strReq = GetReqUrl(mapVals, strSign);
		JSONObject jsonobj= null;
		jsonobj = DoHttpReq(strReq, null, 0);
		Echo("speed : "+m_qwFileSize/(m_qwEndTime - m_qwStartTime) + "byte/s");
		return 0;
	}
	
	public int Upload() {
		try {
			//对于ugc上传，initupload应该在svr调用，本处仅作示例
			int iRet = InitUpload();
			if (iRet != 0) {
				Echo("Init upload failed"+iRet);
				//Report(iRet);
				return iRet;
			}
			for (int i = 0; i < m_arrPartInfo.size(); i++) {
				this.m_arrThreadList.get(i%m_arrThreadList.size()).AddPartIndex(i);
			}
			for (int i = 0; i < m_arrThreadList.size(); i++) {
				this.m_arrThreadList.get(i).start();
			}
			for (int i = 0; i < m_arrThreadList.size(); i++) {
				this.m_arrThreadList.get(i).join();
			}
			for (int i = 0; i < m_arrThreadList.size(); i++) {
				if (m_arrThreadList.get(i).m_iRet != 0)
				{
					Echo("part upload has error " + m_arrThreadList.get(i).m_iRet);
					return m_arrThreadList.get(i).m_iRet;
				}
			}
			//对于ugc上传，FinishUpload应该在svr调用，本处仅作示例
			iRet = FinishUpload();
			if (iRet != 0) {
				Report(iRet);
				Echo("finish failed " + iRet);
				return iRet;
			}
			this.m_qwEndTime = System.currentTimeMillis() / 1000;
			//Report(0);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return 0;
	}
}

