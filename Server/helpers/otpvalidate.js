
export const oneMinuteOtpExpire =async(optTime)=>{

try {
    console.log('timestamp is :--' +optTime);

    const c_datetime= new Date();
    var differencevalue= (optTime- c_datetime.getTime())/1000;
    differencevalue /= 60;
    console.log('expire minutes:--', +Math.abs(differencevalue));
    if(Math.abs(differencevalue)>1){
        return true;
    }
    return false;
} catch (error) {
     console.log(error);
}

}






export const threeMinuteOtpExpire =async(optTime)=>{

    try {
        console.log('timestamp is :--' +optTime);
    
        const c_datetime= new Date();
        var differencevalue= (optTime- c_datetime.getTime())/1000;
        differencevalue /= 60;
        console.log('expire minutes:--', +Math.abs(differencevalue));
        if(Math.abs(differencevalue)>3){
            return true;
        }
        return false;
    } catch (error) {
         console.log(error);
    }
    
    }


