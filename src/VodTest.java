import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import sun.misc.BASE64Encoder;

class HttpSvc {
	public static void main(String[] args) throws Exception {
		 {
			//VodCall 不能复用，每次需要上传文件，或者调用vod api时，务必重新new对象，int后使用
			 
			//for svr普通上传
			/*
			VodCall test = new VodCall();
			test.OpenEcho();
			test.Init("AKIDR20GpXsc4fixxxxxxxbuWQCeTpw9ljzt", "wGxKo4cu6WFBWxxxxxxxbH7BTTiUn4bV", VodCall.USAGE_UPLOAD, 12);
			test.SetFileInfo("D:\\test.mp4", "test", "mp4", 12);
			int ret = test.Upload();
			System.out.printf("%d %s\n", ret, test.m_strFileId);*/
			
			//for ugc上传，实际使用时，需要重写 GetUgcExSign 方法
			/*VodCall test = new VodCall();
			test.OpenEcho();
			test.Init("AKIDR20GpXsc4fixxxxxxxbuWQCeTpw9ljzt", "wGxKo4cu6WFBWxxxxxxxbH7BTTiUn4bV", VodCall.USAGE_UGC_UPLOAD, 12);
			test.SetFileInfo("F:\\the rose.mp3", "test", "mp3", 12);
			int ret = test.Upload();
			System.out.printf("%d %s\n", ret, test.m_strFileId);*/
			
			//for 上传封面方法
			/*VodCall test = new VodCall();
			test.OpenEcho();
			test.Init("AKIDR20GpXsc4fixxxxxxxbuWQCeTpw9ljzt", "wGxKo4cu6WFBWxxxxxxxbH7BTTiUn4bV", VodCall.USAGE_UPLOAD, 12);
			test.SetFileInfo("D:\\QQ图片20170221131620.jpg", "test", "jpg", 12);
			test.AddExtraPara("usage", "1");
			test.AddExtraPara("fileId", "9031868222863204403");
			int ret = test.Upload();
			System.out.printf("%d %s\n", ret, test.m_strFileId);*/
			
			//for REST API调用方法，mapVals中需指定Action+业务参数
			/*VodCall test = new VodCall();
			test.OpenEcho();
			test.Init("AKIDR20GpXsc4fixxxxxxxbuWQCeTpw9ljzt", "wGxKo4cu6WFBWxxxxxxxbH7BTTiUn4bV", VodCall.USAGE_VOD_REST_API_CALL, 0);
			TreeMap<String, Object> mapVals = new TreeMap<String, Object>() {
				{
					put("Action", "DescribeVodPlayUrls");
					put("fileId", "9031868222866819849");
				}
			};
			JSONObject jsObj = test.CallRestApi(mapVals);
			System.out.printf("retCode %d\n", jsObj.getInt("code"));*/
		}
	}
}
