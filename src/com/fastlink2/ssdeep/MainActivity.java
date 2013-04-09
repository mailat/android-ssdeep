package com.fastlink2.ssdeep;

import java.io.File;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.TextView;
import android.app.Activity;

/*
 * Copyright (C) 2013 Marius Mailat http://fastlink2.com/contact.htm
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

public class MainActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		StringBuffer log = new StringBuffer();
		
		//TEST 01: generate a ssdeep signature of 3 files
    	String signature1 = "";
    	String signature2 = "";
    	String signature3 = "";
        try
        {
	        File file = new File( Environment.getExternalStorageDirectory() + "avlscan.log");
	        Ssdeep testSsdeepGenerate = new Ssdeep();
	        signature1 = testSsdeepGenerate.fuzzy_hash_file(file);
			log.append("\r\n").append(signature1);
			
	        file = new File(Environment.getExternalStorageDirectory() + "iGO2.apk");
	        testSsdeepGenerate = new Ssdeep();
	        signature2 = testSsdeepGenerate.fuzzy_hash_file(file);
			log.append("\r\n").append(signature2);
			
	        file = new File(Environment.getExternalStorageDirectory() + "iGO1.apk");
	        testSsdeepGenerate = new Ssdeep();
	        signature3 = testSsdeepGenerate.fuzzy_hash_file(file);
			log.append("\r\n").append(signature3);
			
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }    
        
		//TEST 02: compare 2 ssdeep signatures	
    	try
    	{
    		Ssdeep testSsdeep = new Ssdeep();
    		String resultSignatureCompare = testSsdeep.Compare(new SpamSumSignature(signature1), new SpamSumSignature(signature2)) + "";
    		log.append("\r\n").append("1 vs 2=" + resultSignatureCompare);
    		
    		testSsdeep = new Ssdeep();
    		resultSignatureCompare = testSsdeep.Compare(new SpamSumSignature(signature2), new SpamSumSignature(signature3)) + "";
    		log.append("\r\n").append("2 vs 3=" + resultSignatureCompare);
    	}
    	catch (Exception e)
    	{
    		e.printStackTrace();
    	}
    	
    	//Test 03: generate the ssdeep for a whole folder
    	try
    	{
	    	File dir = new File(Environment.getExternalStorageDirectory() + "TestApk");
	    	Ssdeep testSsdeepGenerate;
	    	String signature;
	    	for (File childFile : dir.listFiles()) {
	  	        testSsdeepGenerate = new Ssdeep();
	  	        signature = testSsdeepGenerate.fuzzy_hash_file(childFile);
	  	        log.append("\r\n").append(childFile.getName() + " ssdeep: " + signature);
	    	  }
    	}
    	catch (Exception e)
    	{
    		e.printStackTrace();
    	}
    	
    	TextView logger = (TextView) this.findViewById(R.id.logger);
    	logger.setText(log.toString());
    	Log.d("TEST", log.toString());   	
	}
}