package academy.devdojo.youtube.course;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan({"academy.devdojo.youtube.core.model"})
@EnableJpaRepositories({"academy.devdojo.youtube.core.repository"})
public class CourseApplication implements CommandLineRunner{

    public static void main(String[] args) {
        SpringApplication.run(CourseApplication.class, args);
    }

	@Override
	public void run(String... args) throws Exception {
	    String sDate1="15/08/2021";  
	    Date date1=new SimpleDateFormat("dd/MM/yyyy").parse(sDate1);  
	    System.out.println(sDate1+"\t"+date1);  
		
		
	}

}
