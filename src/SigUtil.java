public class SigUtil {

    private static final String DEFAULT_ENCODE = "UTF-8";

    private static final String DEFAULT_SIG_NAME = "sig";

    private static Logger logger = LoggerFactory.getLogger(SigUtil.class);

    // MD��ʼ��
    private static MessageDigest md = null;

    static {
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * ����json��sig
     *
     * @param jsonObject
     * @param secretKey
     * @return
     */
    public static String calculateSig(JSONObject jsonObject, String secretKey) {
        Map<String,String> paramMap=jsonToMap(jsonObject);
        return calculateSig(paramMap,secretKey);
    }

    /**
     * ���ڽ���������Ϊsig
     *
     * @param param     Ҫ�ύ�Ĳ���
     * @param secretKey ��Կ
     * @return
     */
    public static String calculateSig(Map<String, String> param, String secretKey) {
        if (param == null || param.size() == 0) {
            throw new IllegalArgumentException("param is null or empty");
        }
        //ɾ��keyΪnull��entry
        param.remove(null);
        //����key
        String[] keys = new String[param.size()];
        List<String> keyList = Arrays.asList(param.keySet().toArray(keys));
        Collections.sort(keyList);

        //ƴ��k1=v1k2=v2
        StringBuilder paramStrBuilder = new StringBuilder();
        for (String key : keyList) {
            if(key!=null&&param.get(key)!=null){
                paramStrBuilder.append(key);
                paramStrBuilder.append("=");
                paramStrBuilder.append(param.get(key).toString());
            }
        }
        //ƴ��secretKey
        paramStrBuilder.append(secretKey);
        String encodeParam = "";
        try {
            encodeParam = URLEncoder.encode(paramStrBuilder.toString(), DEFAULT_ENCODE);
        } catch (UnsupportedEncodingException e) {
            logger.error(e.getMessage());
        }

        byte b[];
        synchronized(md){
            md.update(encodeParam.getBytes());
            b= md.digest();
        }

        String sig= new String(Hex.encodeHex(b));
        if(logger.isDebugEnabled()){
            logger.info("calculateSig: sig="+sig+"  , map="+paramStrBuilder.toString());
        }
        return sig;
    }


    /**
     * ���sig�Ƿ������ȷ
     *
     * @param param
     * @param secretKey
     * @return
     */
    public static boolean checkSig(Map<String, String> param, String secretKey) {
        return checkSig(DEFAULT_SIG_NAME, param, secretKey);
    }

    /**
     * ͨ��jsonУ��sig�Ƿ���ȷ
     * @param jsonObject
     * @param secretKey
     * @return
     */
    public static boolean checkSig(JSONObject jsonObject, String secretKey) {
        Map<String,String> paramMap=jsonToMap(jsonObject);
        return checkSig(DEFAULT_SIG_NAME, paramMap, secretKey);
    }

    /**
     * У��ǩ���Ƿ���ȷ
     *
     * @param sigName   ǩ����map�е�key
     * @param param     �յ��Ĳ���
     * @param secretKey ��Կ
     * @return
     */
    public static boolean checkSig(String sigName, Map<String, String> param, String secretKey) {
        if (param == null || param.size() == 0) {
            throw new IllegalArgumentException("param is null or empty");
        }
        if (StringUtils.isBlank(sigName)) {
            throw new IllegalArgumentException("sigName is blank");
        }
        if (StringUtils.isBlank(secretKey)) {
            throw new IllegalArgumentException("secretKey is blank");
        }


        String sig = param.get(sigName);
        if (StringUtils.isBlank(sig)) {
            throw new IllegalArgumentException("secretKey is blank");
        }

        param.remove(sigName);

        String calculateSig = calculateSig(param, secretKey);

        System.out.println("Compute: "+calculateSig+",Origin:"+sig);

        if (sig.trim().equals(calculateSig)) {
            return true;
        }

        return false;
    }

    private static Map<String,String> jsonToMap(JSONObject jsonObject){
        if(jsonObject==null||jsonObject.size()==0){
            throw new IllegalArgumentException("jsonObject is empty");
        }

        Set<String> keySet = jsonObject.keySet();

        Map<String,String> paramMap=new HashMap<String, String>(keySet.size());

        for(String key:keySet){
            paramMap.put(key,jsonObject.getString(key));
        }

        return paramMap;
    }

    /**
     * ר���ڴ���processor�յ�������push server����Ϣ
     * @param packet
     * @param secretKey
     * @return
     */
    public static boolean checkSig(Packet packet, String secretKey){
        JSONObject paramJson=JSONObject.parseObject(packet.toJSON());
        //�����ֶ���push server��ӵģ����ǿͻ��˷��͵��ֶ�
        paramJson.remove("type");
        paramJson.remove("node");
        paramJson.remove("at");
        paramJson.remove("connid");
        paramJson.remove("clientid");
        return checkSig(paramJson,secretKey);
    }



//    public static void main(String[] args){
//
//        String secretKey="46de137579bc4309bddf439064468600";
//
//        //����map
//        Map<String,String> param=new HashMap<String, String>();
//        param.put(null,null);
//        param.put("udid","A0000040E4BF87");
//        param.put("appid","1100");
//        param.put("null",null);
//        long stamp=System.currentTimeMillis();
//        param.put("stamp",stamp+"");
//
//        String sig=calculateSig(param,secretKey);
//
//        param.put(DEFAULT_SIG_NAME,sig);
//
//        System.out.println(checkSig(param,secretKey));
//
//        //����json
//        JSONObject jsonObject=new JSONObject();
//        jsonObject.put("app_version","1.0");
//        jsonObject.put("appid","1001");
//        jsonObject.put("stamp","1378377621347");
//        jsonObject.put("sdk_version","1");
//        jsonObject.put("pack","com.sogou.push.test");
//
//        String sigJson=calculateSig(jsonObject,secretKey);
//        System.out.println(sigJson);
//        jsonObject.put(DEFAULT_SIG_NAME,sigJson);
//
//        System.out.println(checkSig(jsonObject,secretKey));
//
//    }

}